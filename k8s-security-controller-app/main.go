package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var cronController *CronController

func main() {
	var kubeconfig string
	var master string
	var mode string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.StringVar(&mode, "mode", "controller", "running mode: controller or agent")
	flag.Parse()

	log.Printf("Starting in %s mode", mode)

	// Создаем конфигурацию для подключения к Kubernetes
	config, err := buildConfig(master, kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	// Создаем клиент Kubernetes
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Загружаем конфигурацию безопасности
	log.Println("Next step - loading the security config")
	securityConfig, err := loadSecurityConfig()
	if err != nil {
		log.Printf("Warning: Could not load security config, using defaults: %v", err)
		securityConfig = getDefaultSecurityConfig()
	}

	// Создаем контроллер cron
	if securityConfig.Cron.Enabled {
		cronController = NewCronController(clientset, config, securityConfig)
	}

	// Запускаем контроллер
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Обработка сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received termination signal, shutting down...")
		cancel()
	}()

	log.Println("Starting Kubernetes Security Controller - Cron Monitor")
	log.Printf("Monitoring interval: %v", securityConfig.Cron.MonitoringInterval)

	if mode == "agent" {
		// Агент мониторит только поды на своей ноде
		nodeName := os.Getenv("NODE_NAME")
		if nodeName == "" {
			log.Fatal("NODE_NAME environment variable is required for agent mode")
		}
		log.Printf("Starting agent mode for node: %s", nodeName)
		if securityConfig.Cron.Enabled {
			cronController.StartAgentMonitoring(ctx, nodeName)
		}
	} else {
		// Контроллер работает как управляющий сервис
		log.Println("Starting controller mode")
		if securityConfig.Cron.Enabled {
			cronController.StartControllerService(ctx)
		}
	}
}

func buildConfig(masterUrl, kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags(masterUrl, kubeconfigPath)
	}
	return rest.InClusterConfig()
}

func getDefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Cron: CronConfig{
			Enabled:            true,
			MonitoringInterval: 30 * time.Second,
			MonitoredPaths: []string{
				"/etc/crontab",
				"/etc/cron.d/",
				"/var/spool/cron/crontabs/",
				"/etc/cron.hourly/",
				"/etc/cron.daily/",
				"/etc/cron.weekly/",
				"/etc/cron.monthly/",
			},
			SuspiciousPatterns: []string{
				"* * * * * *", // слишком частое выполнение
				"*/1 *",       // каждую минуту
				"sh -c",       // выполнение shell-команд
				"bash -c",     // выполнение bash-команд
				"wget",        // скачивание файлов
				"curl",        // HTTP-запросы
				"nc ",         // netcat
				"ncat",        // ncat
				"/tmp/",       // использование временных директорий
				"/dev/shm/",   // shared memory
			},
			AllowedCommands: []string{
				"/usr/bin/apt",
				"/usr/bin/yum",
				"/usr/bin/systemctl",
				"/usr/bin/logrotate",
			},
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

func handleAllowedCommands(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cronController.config.Cron.AllowedCommands)
	case "POST":
		var command string
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cronController.AddAllowedCommand(command)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleSuspiciousPatterns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cronController.config.Cron.SuspiciousPatterns)
	case "POST":
		var pattern string
		if err := json.NewDecoder(r.Body).Decode(&pattern); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cronController.AddSuspiciousPattern(pattern)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cronController.config)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
