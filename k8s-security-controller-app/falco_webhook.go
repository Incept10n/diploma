package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type FalcoWebhookServer struct {
	clientset *kubernetes.Clientset
	restCfg   *rest.Config
	secret    string
}

func NewFalcoWebhookServer(cs *kubernetes.Clientset, cfg *rest.Config, secret string) *FalcoWebhookServer {
	return &FalcoWebhookServer{clientset: cs, restCfg: cfg, secret: secret}
}

func (s *FalcoWebhookServer) Start(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/falco/event", s.handleFalcoEvent)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	log.Printf("Falco webhook server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("falco webhook server error: %v", err)
	}
}

func (s *FalcoWebhookServer) handleFalcoEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(400)
		return
	}
	defer r.Body.Close()

	var evt map[string]any
	if err := json.Unmarshal(body, &evt); err != nil {
		log.Printf("falco webhook: invalid json: %v", err)
		w.WriteHeader(400)
		return
	}

	ns, pod, container, rule := extractK8s(evt)
	log.Printf("Falco event received: rule=%q ns=%q pod=%q container=%q", rule, ns, pod, container)

	if ns != "" && pod != "" {
		if err := s.clientset.CoreV1().Pods(ns).Delete(r.Context(), pod, *deleteOpts()); err != nil {
			log.Printf("falco remediation: failed to delete pod %s/%s: %v", ns, pod, err)
			w.WriteHeader(500)
			return
		}
		log.Printf("falco remediation: deleted pod %s/%s due to rule=%q", ns, pod, rule)
	}

	w.WriteHeader(200)
}

func extractK8s(evt map[string]any) (ns, pod, container, rule string) {
	rule, _ = evt["rule"].(string)
	if rule == "" {
		rule, _ = evt["ruleName"].(string)
	}

	ns = getString(evt, "k8s.ns.name", "output_fields.k8s.ns.name", "namespace")
	pod = getString(evt, "k8s.pod.name", "output_fields.k8s.pod.name", "pod")
	container = getString(evt, "container.name", "output_fields.container.name", "container")

	if ns == "" || pod == "" {
		if out, ok := evt["output"].(string); ok {
			ns = fallbackFind(out, "k8s.ns.name=")
			pod = fallbackFind(out, "k8s.pod.name=")
		}
	}

	return
}

func getString(evt map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := evt[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			if strings.Contains(k, ".") {
				continue
			}
		}
		if strings.HasPrefix(k, "output_fields.") {
			if of, ok := evt["output_fields"].(map[string]any); ok {
				sub := strings.TrimPrefix(k, "output_fields.")
				if v, ok := of[sub]; ok {
					if s, ok := v.(string); ok && s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

func fallbackFind(out, prefix string) string {
	i := strings.Index(out, prefix)
	if i == -1 {
		return ""
	}
	s := out[i+len(prefix):]
	for j := 0; j < len(s); j++ {
		if s[j] == ' ' || s[j] == ')' || s[j] == ',' {
			return s[:j]
		}
	}
	return s
}

func deleteOpts() *metav1.DeleteOptions {
	grace := int64(0)
	return &metav1.DeleteOptions{GracePeriodSeconds: &grace}
}
