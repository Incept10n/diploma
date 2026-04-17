package main

import (
	"io/ioutil"
	"log"
	"time"

	"gopkg.in/yaml.v2"
)

type SecurityConfig struct {
	Cron    CronConfig    `yaml:"cron"`
	Logging LoggingConfig `yaml:"logging"`
}

type CronConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MonitoringInterval time.Duration `yaml:"monitoringInterval"`
	MonitoredPaths     []string      `yaml:"monitoredPaths"`
	SuspiciousPatterns []string      `yaml:"suspiciousPatterns"`
	AllowedCommands    []string      `yaml:"allowedCommands"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

func loadSecurityConfig() (*SecurityConfig, error) {
	// Пытаемся загрузить из ConfigMap (внутри контейнера)
	log.Println("Setting the path for security-config.yaml")
	configPath := "/config/security-config-cron.yaml"
	if data, err := ioutil.ReadFile(configPath); err == nil {
		log.Println("Trying to load the security-config.yaml")
		var config SecurityConfig
		if err := yaml.Unmarshal(data, &config); err == nil {
			log.Println("Error unmarshling")
			// Конвертируем строку времени в time.Duration
			return &config, nil
		}
	}

	// Если ConfigMap недоступен, используем дефолтную конфигурацию
	log.Println("Cron monitoring is disabled")
	// log.Println("Loading default security-config.yaml")
	return getDefaultSecurityConfig(), nil
}
