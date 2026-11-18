package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type binding struct {
	PodUID        string `json:"pod_uid"`
	SandboxID     string `json:"sandbox_id"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Attempt       uint32 `json:"attempt"`
	ImageRef      string `json:"image_ref"`
}

type containerInfo struct {
	SandboxID   string                   `json:"sandboxID"`
	RuntimeType string                   `json:"runtimeType"`
	Snapshotter string                   `json:"snapshotter"`
	Config      *runtime.ContainerConfig `json:"config"`
}

type probeProfile struct {
	mode      string
	namespace string
	pod       string
	attempt   uint32
}

var (
	imageDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	podUID      = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)
	dnsLabel    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

func parseProfile(args []string) (probeProfile, error) {
	if len(args) == 4 {
		switch args[3] {
		case "absent", "kata", "kata-running", "runc":
			return probeProfile{mode: args[3], namespace: "onb17-local", pod: "onb17-worker-proof"}, nil
		}
	}
	if len(args) != 7 || args[3] != "gcp-kata" {
		return probeProfile{}, errors.New("usage: worker-readback CRI_SOCKET POD_UID IMAGE kata|kata-running|runc|absent; for gcp-kata append POD_NAMESPACE POD_NAME ATTEMPT")
	}
	name, digest, ok := strings.Cut(args[2], "@")
	if !podUID.MatchString(args[1]) || !ok || name == "" || strings.ContainsAny(name, " \t\r\n") || !imageDigest.MatchString(digest) {
		return probeProfile{}, errors.New("gcp-kata requires a Pod UID and a digest-pinned image")
	}
	if !dnsLabel.MatchString(args[4]) || len(args[5]) > 253 {
		return probeProfile{}, errors.New("gcp-kata requires an exact Pod namespace and name")
	}
	for _, label := range strings.Split(args[5], ".") {
		if !dnsLabel.MatchString(label) {
			return probeProfile{}, errors.New("gcp-kata requires an exact Pod namespace and name")
		}
	}
	attempt, err := strconv.ParseUint(args[6], 10, 32)
	if err != nil {
		return probeProfile{}, errors.New("gcp-kata requires a valid CRI container attempt")
	}
	return probeProfile{mode: args[3], namespace: args[4], pod: args[5], attempt: uint32(attempt)}, nil
}

func readImageBlob(path, digest string, result any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	const maxSize = 1 << 20
	blob, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return err
	}
	if len(blob) > maxSize || fmt.Sprintf("sha256:%x", sha256.Sum256(blob)) != digest {
		return fmt.Errorf("local OCI blob does not match its bounded expected digest")
	}
	return json.Unmarshal(blob, result)
}

func imageLayer(mode, path, digest string) (string, error) {
	if mode == "manifest-config" {
		type descriptor struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}
		var manifest struct {
			SchemaVersion int          `json:"schemaVersion"`
			MediaType     string       `json:"mediaType"`
			Config        descriptor   `json:"config"`
			Layers        []descriptor `json:"layers"`
		}
		if err := readImageBlob(path, digest, &manifest); err != nil {
			return "", err
		}
		if manifest.SchemaVersion != 2 || manifest.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
			manifest.Config.MediaType != "application/vnd.oci.image.config.v1+json" ||
			!imageDigest.MatchString(manifest.Config.Digest) || manifest.Config.Size <= 0 || len(manifest.Layers) != 1 ||
			!strings.HasSuffix(manifest.Layers[0].MediaType, "+encrypted") ||
			!imageDigest.MatchString(manifest.Layers[0].Digest) || manifest.Layers[0].Size <= 0 {
			return "", fmt.Errorf("expected exact one-layer encrypted OCI workload manifest")
		}
		return manifest.Config.Digest, nil
	}
	var config struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := readImageBlob(path, digest, &config); err != nil {
		return "", err
	}
	if config.Architecture != "amd64" || config.OS != "linux" || config.RootFS.Type != "layers" ||
		len(config.RootFS.DiffIDs) != 1 || !imageDigest.MatchString(config.RootFS.DiffIDs[0]) {
		return "", fmt.Errorf("expected a linux/amd64 OCI config with one rootfs DiffID")
	}
	return config.RootFS.DiffIDs[0], nil
}

func main() {
	if len(os.Args) == 4 && (os.Args[1] == "manifest-config" || os.Args[1] == "config-diffid") {
		result, err := imageLayer(os.Args[1], os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(result)
		return
	}
	profile, err := parseProfile(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], profile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(socket, uid, image string, profile probeProfile) error {
	conn, err := grpc.NewClient("passthrough:///onb17-local-cri",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := runtime.NewRuntimeServiceClient(conn)
	timeout := 30 * time.Second
	if profile.mode == "absent" {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var lastErr error
	for ctx.Err() == nil {
		var found *binding
		var count int
		found, count, lastErr = inspect(ctx, client, uid, image, profile)
		if lastErr == nil {
			if profile.mode == "absent" && count == 0 {
				fmt.Println("ONB17_WORKER_CRI_GONE", uid)
				return nil
			}
			if found != nil {
				data, err := json.Marshal(found)
				if err != nil {
					return err
				}
				fmt.Printf("ONB17_WORKER_READBACK %s\n", data)
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.Join(errors.New("timed out reading the matching worker CRI objects"), lastErr)
}

func inspect(ctx context.Context, client runtime.RuntimeServiceClient, uid, image string, profile probeProfile) (*binding, int, error) {
	labels := map[string]string{"io.kubernetes.pod.uid": uid}
	sandboxes, err := client.ListPodSandbox(ctx, &runtime.ListPodSandboxRequest{
		Filter: &runtime.PodSandboxFilter{LabelSelector: labels},
	})
	if err != nil {
		return nil, 0, err
	}
	containers, err := client.ListContainers(ctx, &runtime.ListContainersRequest{
		Filter: &runtime.ContainerFilter{LabelSelector: labels},
	})
	if err != nil {
		return nil, 0, err
	}
	count := len(sandboxes.Items) + len(containers.Containers)
	if profile.mode == "absent" || len(sandboxes.Items) != 1 || len(containers.Containers) != 1 {
		return nil, count, nil
	}

	sandbox, app := sandboxes.Items[0], containers.Containers[0]
	if sandbox.GetMetadata().GetUid() != uid || sandbox.GetMetadata().GetNamespace() != profile.namespace ||
		sandbox.GetMetadata().GetName() != profile.pod ||
		app.GetPodSandboxId() != sandbox.GetId() || app.GetId() == "" || app.GetId() == sandbox.GetId() ||
		app.GetMetadata().GetName() != "workload" {
		return nil, count, fmt.Errorf("worker CRI metadata mismatch for Pod %s", uid)
	}
	if profile.mode == "gcp-kata" &&
		(!containerID.MatchString(sandbox.GetId()) || !containerID.MatchString(app.GetId()) ||
			app.GetMetadata().GetAttempt() != profile.attempt) {
		return nil, count, fmt.Errorf("worker CRI full IDs or attempt mismatch for Pod %s", uid)
	}
	response, err := client.ContainerStatus(ctx, &runtime.ContainerStatusRequest{ContainerId: app.GetId(), Verbose: true})
	if err != nil {
		return nil, count, err
	}
	status := response.GetStatus()
	if status.GetId() != app.GetId() || status.GetMetadata().GetAttempt() != app.GetMetadata().GetAttempt() ||
		status.GetMetadata().GetName() != app.GetMetadata().GetName() ||
		status.GetLabels()["io.kubernetes.pod.uid"] != uid {
		return nil, count, fmt.Errorf("worker CRI container status mismatch for Pod %s", uid)
	}
	var info containerInfo
	if err := json.Unmarshal([]byte(response.GetInfo()["info"]), &info); err != nil {
		return nil, count, fmt.Errorf("decoding worker CRI container info: %w", err)
	}
	if info.SandboxID != sandbox.GetId() || info.Config.GetMetadata().GetName() != app.GetMetadata().GetName() ||
		info.Config.GetMetadata().GetAttempt() != app.GetMetadata().GetAttempt() || info.Config.GetLabels()["io.kubernetes.pod.uid"] != uid {
		return nil, count, fmt.Errorf("worker persisted CRI config mismatch for Pod %s", uid)
	}
	if profile.mode == "kata" || profile.mode == "gcp-kata" || profile.mode == "kata-running" {
		expectedState := runtime.ContainerState_CONTAINER_CREATED
		if profile.mode == "kata-running" {
			expectedState = runtime.ContainerState_CONTAINER_RUNNING
		}
		if app.GetState() != expectedState || status.GetState() != expectedState {
			return nil, count, fmt.Errorf("expected Kata application state %s, list state %s status state %s",
				expectedState, app.GetState(), status.GetState())
		}
		sandboxResponse, err := client.PodSandboxStatus(ctx, &runtime.PodSandboxStatusRequest{PodSandboxId: sandbox.GetId()})
		if err != nil {
			return nil, count, err
		}
		sandboxStatus := sandboxResponse.GetStatus()
		handler := sandboxStatus.GetRuntimeHandler()
		validRuntime := (handler == "" || handler == "kata") && info.RuntimeType == "io.containerd.kata.v2"
		if profile.mode == "gcp-kata" {
			validRuntime = handler == "kata-remote" && info.RuntimeType == "io.containerd.kata-remote.v2" &&
				info.Snapshotter == "nydus-for-kata-tee"
		}
		if sandboxStatus.GetId() != sandbox.GetId() || sandboxStatus.GetMetadata().GetUid() != uid ||
			sandboxStatus.GetState() != runtime.PodSandboxState_SANDBOX_READY || !validRuntime {
			return nil, count, fmt.Errorf("expected ready Kata sandbox for Pod %s, got %s handler %q runtime %q snapshotter %q",
				uid, sandboxStatus.GetState(), handler, info.RuntimeType, info.Snapshotter)
		}
		if profile.mode == "gcp-kata" &&
			(sandboxStatus.GetMetadata().GetNamespace() != profile.namespace || sandboxStatus.GetMetadata().GetName() != profile.pod) {
			return nil, count, fmt.Errorf("worker CRI sandbox status identity mismatch for Pod %s", uid)
		}
	}
	// The public status may resolve the image to its import tag. The verbose
	// worker readback retains the original image string persisted by CRI Create.
	workerImage := info.Config.GetImage().GetUserSpecifiedImage()
	if workerImage != image {
		return nil, count, fmt.Errorf("worker CRI image %q differs from API image %q", workerImage, image)
	}
	return &binding{
		PodUID:        sandbox.GetMetadata().GetUid(),
		SandboxID:     sandbox.GetId(),
		ContainerID:   app.GetId(),
		ContainerName: app.GetMetadata().GetName(),
		Attempt:       app.GetMetadata().GetAttempt(),
		ImageRef:      workerImage,
	}, count, nil
}
