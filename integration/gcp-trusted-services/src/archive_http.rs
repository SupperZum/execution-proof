use crate::{
    archive::{Archive, DeliveryScope},
    gcp_launch_http::{self, ResourceDecisionResponse},
    gcp_launch_resource::LaunchResourceService,
};
use actix_web::{body::to_bytes_limited, dev::ServiceResponse, HttpResponse};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{gcp_policy_receipt::GcpLaunchPolicyAggregateV2, Signed};

pub(crate) async fn commit_response(
    response: ServiceResponse,
    resource: &LaunchResourceService,
    archive: &Archive,
    delivery_scope: &DeliveryScope,
) -> actix_web::Result<ServiceResponse> {
    let needs_archive = response.request().path()
        == format!("{}/resource-decision", gcp_launch_http::LAUNCH_HTTP_PREFIX);
    let needs_delivery = response.request().path()
        == format!(
            "{}/credential-delivery",
            gcp_launch_http::LAUNCH_HTTP_PREFIX
        );
    if !(needs_archive || needs_delivery) || response.status() != actix_web::http::StatusCode::OK {
        return Ok(response.map_into_boxed_body());
    }
    let (request, response) = response.into_parts();
    let status = response.status();
    let bytes = to_bytes_limited(response.into_body(), 128 << 10)
        .await
        .map_err(|_| actix_web::error::ErrorServiceUnavailable("policy response bound"))?
        .map_err(|_| actix_web::error::ErrorServiceUnavailable("policy response unavailable"))?;
    let committed = (|| -> Result<()> {
        if needs_delivery {
            return archive.store_delivery_response(&bytes, delivery_scope);
        }
        let response: ResourceDecisionResponse = serde_json::from_slice(&bytes)?;
        let wire = STANDARD.decode(
            response
                .signed_aggregate_b64
                .ok_or_else(|| anyhow::anyhow!("aggregate unavailable"))?,
        )?;
        ensure!(wire.len() <= 32 << 10, "aggregate bound");
        let aggregate: Signed<GcpLaunchPolicyAggregateV2> = serde_json::from_slice(&wire)?;
        let digest = aggregate.statement.digest_sha384()?;
        let snapshot = resource.export_policy_capture(&aggregate.statement.session_id, &digest)?;
        ensure!(
            snapshot.signed_aggregate_json() == wire,
            "archive service identity mismatch"
        );
        archive.store(&snapshot)
    })();
    committed.map_err(|_| {
        actix_web::error::ErrorServiceUnavailable("original policy archive unavailable")
    })?;
    Ok(ServiceResponse::new(
        request,
        HttpResponse::build(status)
            .content_type("application/json")
            .body(bytes),
    )
    .map_into_boxed_body())
}
