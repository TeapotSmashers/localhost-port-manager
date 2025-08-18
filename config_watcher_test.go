package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfigWatcher tests configuration file watching functionality
func TestConfigWatcher(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configFile := filepath.Join(tempDir, "config.txt")
	logger := log.New(io.Discard, "", 0)

	// Create initial config file
	initialConfig := "3000\n8080\n"
	err = os.WriteFile(configFile, []byte(initialConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to create initial config: %v", err)
	}

	t.Run("NewConfigWatcher", func(t *testing.T) {
		watcher := NewConfigWatcher(configFile, logger)
		if watcher == nil {
			t.Errorf("NewConfigWatcher should not return nil")
			return
		}
		if watcher.configPath != configFile {
			t.Errorf("Expected config path %s, got %s", configFile, watcher.configPath)
		}
	})

	t.Run("Start and Stop", func(t *testing.T) {
		watcher := NewConfigWatcher(configFile, logger)

		err := watcher.Start()
		if err != nil {
			t.Errorf("Failed to start watcher: %v", err)
		}

		// Stop should not panic
		watcher.Stop()

		// Multiple stops should not panic
		watcher.Stop()
	})

	t.Run("Config file change detection", func(t *testing.T) {
		watcher := NewConfigWatcher(configFile, logger)

		err := watcher.Start()
		if err != nil {
			t.Fatalf("Failed to start watcher: %v", err)
		}
		defer watcher.Stop()

		// Update config file
		newConfig := "9000\n9001\n"
		err = os.WriteFile(configFile, []byte(newConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to update config file: %v", err)
		}

		// Wait for change detection (with timeout)
		timeout := time.After(5 * time.Second)
		select {
		case newPorts := <-watcher.ReloadChan():
			if len(newPorts) != 2 {
				t.Errorf("Expected 2 ports, got %d", len(newPorts))
			}
			if newPorts[0] != 9000 || newPorts[1] != 9001 {
				t.Errorf("Expected ports [9000, 9001], got %v", newPorts)
			}
		case err := <-watcher.ErrorChan():
			t.Errorf("Unexpected error: %v", err)
		case <-timeout:
			t.Errorf("Config change detection timed out")
		}
	})

	t.Run("Invalid config file handling", func(t *testing.T) {
		watcher := NewConfigWatcher(configFile, logger)

		err := watcher.Start()
		if err != nil {
			t.Fatalf("Failed to start watcher: %v", err)
		}
		defer watcher.Stop()

		// Write invalid config
		invalidConfig := "3000\ninvalid_port\n8080\n"
		err = os.WriteFile(configFile, []byte(invalidConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid config: %v", err)
		}

		// Should receive error
		timeout := time.After(5 * time.Second)
		select {
		case <-watcher.ReloadChan():
			t.Errorf("Should not receive valid config for invalid file")
		case err := <-watcher.ErrorChan():
			if err == nil {
				t.Errorf("Should receive error for invalid config")
			}
		case <-timeout:
			t.Errorf("Error detection timed out")
		}
	})
}

// TestConfigWatcherEdgeCases tests edge cases for config watcher
func TestConfigWatcherEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-watcher-edge-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logger := log.New(io.Discard, "", 0)

	t.Run("Missing config file", func(t *testing.T) {
		missingFile := filepath.Join(tempDir, "missing.txt")
		watcher := NewConfigWatcher(missingFile, logger)

		err := watcher.Start()
		if err == nil {
			t.Errorf("Should fail to start watcher for missing file")
		}
	})

	t.Run("Multiple rapid changes", func(t *testing.T) {
		configFile := filepath.Join(tempDir, "rapid-config.txt")

		// Create initial config
		err := os.WriteFile(configFile, []byte("3000\n"), 0644)
		if err != nil {
			t.Fatalf("Failed to create config: %v", err)
		}

		watcher := NewConfigWatcher(configFile, logger)
		err = watcher.Start()
		if err != nil {
			t.Fatalf("Failed to start watcher: %v", err)
		}
		defer watcher.Stop()

		// Make multiple rapid changes
		configs := []string{
			"8080\n",
			"5173\n",
			"9000\n",
		}

		for i, config := range configs {
			err = os.WriteFile(configFile, []byte(config), 0644)
			if err != nil {
				t.Fatalf("Failed to write config %d: %v", i, err)
			}
			time.Sleep(100 * time.Millisecond) // Small delay between changes
		}

		// Should eventually receive the last change
		timeout := time.After(10 * time.Second)
		received := false

		for !received {
			select {
			case newPorts := <-watcher.ReloadChan():
				if len(newPorts) == 1 && newPorts[0] == 9000 {
					received = true
				}
				// Continue receiving until we get the expected final state
			case err := <-watcher.ErrorChan():
				t.Errorf("Unexpected error: %v", err)
				return
			case <-timeout:
				t.Errorf("Did not receive expected final config")
				return
			}
		}
	})
}
