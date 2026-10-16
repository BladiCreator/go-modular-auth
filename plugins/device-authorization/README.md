# GoModularAuth Device Authorization Plugin (`gomodularauth-device-authorization`)

`gomodularauth-device-authorization` implements the **RFC 8628 OAuth 2.0 Device Authorization Grant** for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth). It enables authentication on internet-connected devices with limited user input capabilities (Smart TVs, CLI tools, media streamers, game consoles, IoT devices) through a secondary browser session.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/device-authorization
```

## Quick Start

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	deviceauth "github.com/BladiCreator/go-modular-auth/plugins/device-authorization"
	"github.com/BladiCreator/go-modular-auth/plugins/device-authorization/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

func main() {
	ctx := context.Background()

	// 1. Initialize storage adapters

	// 2. Configure GoModularAuth with Device Authorization Plugin
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			deviceauth.New(
				deviceauth.WithVerificationURI("https://auth.example.com/device"),
				deviceauth.WithExpiresIn(10*time.Minute),
				deviceauth.WithPollingInterval(5*time.Second),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 3. Resolve DeviceAuthorization Capability
	devAuth, err := auth.Get[plugins.DeviceAuthorization](a)
	if err != nil {
		log.Fatalf("failed to resolve capability: %v", err)
	}

	// 4. Device starts authorization flow (CLI or Smart TV)
	resp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "smart_tv_app",
		Scope:    "read_profile stream_video",
	})
	if err != nil {
		log.Fatalf("failed to start device flow: %v", err)
	}

	fmt.Printf("Please visit: %s\n", resp.VerificationURI)
	fmt.Printf("Enter Code:   %s\n", resp.UserCode)

	// 5. Device polls token endpoint
	for {
		time.Sleep(time.Duration(resp.Interval) * time.Second)

		pollResp, err := devAuth.Poll(ctx, deviceauth.PollInput{
			DeviceCode: resp.DeviceCode,
			ClientID:   "smart_tv_app",
		})
		if errors.Is(err, deviceauth.ErrAuthorizationPending) {
			fmt.Println("Waiting for user authorization...")
			continue
		}
		if errors.Is(err, deviceauth.ErrSlowDown) {
			fmt.Println("Polling too quickly; slowing down...")
			resp.Interval += 5
			continue
		}
		if err != nil {
			log.Fatalf("polling failed: %v", err)
		}

		fmt.Printf("Authorization successful! Session Token: %s\n", pollResp.Token)
		break
	}
}
```

Detailed guide: [**`doc/plugins/device-authorization.md`**](../../doc/plugins/device-authorization.md).
