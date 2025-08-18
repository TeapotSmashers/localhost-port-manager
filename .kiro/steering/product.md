# Product Overview

Port Redirect Service is a lightweight Go service that operates in two deployment modes:

## Core Functionality
- **Local Mode**: Modifies `/etc/hosts` to redirect domains like `3000.local` to `localhost:3000` for development workstations
- **Web Service Mode**: Acts as a deployed service that redirects subdomain requests like `3000.yourdomain.com` to localhost ports

## Key Features
- Dual deployment modes (Local/Web Service)
- Dynamic configuration with hot-reload
- Cross-platform support (macOS launchd, Linux systemd)
- Web status interface with metrics
- Safe hosts file management with automatic backup
- Domain pattern matching with flexible subdomain patterns
- Optional rate limiting for web service mode
- Comprehensive logging and error handling
- Single binary with no external dependencies

## Target Use Cases
- **Local Development**: Simplify port-based development workflows
- **Team Development**: Provide consistent domain access across team members
- **Staging/Production**: Enable subdomain-based service access in deployed environments
- **Microservices**: Facilitate port-based routing for microservice architectures

## Architecture
The service uses a mode-aware handler system that switches behavior based on deployment configuration, supporting both local hosts file modification and web-based subdomain routing.