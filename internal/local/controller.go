/*
Copyright 2024 Dan Molik.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package local

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/setting"
)

type Local struct {
	ctx context.Context
}

// NewLocal returns a new Local
func New(ctx context.Context) *Local {
	if ctx == nil {
		ctx = context.TODO()
	}
	return &Local{ctx: ctx}
}

// Reconcile reads that state of the cluster for a Local object and makes changes based on the state read
// and what is in the Local.Spec
func (l *Local) Start() error {
	for {
		if err := l.reconcileAdminPassword(); err != nil {
			log.Printf("unable to reconcile admin password [%v]", err)
		}
		time.Sleep(7 * time.Second)
	}
}

// Ensure ADMIN PASSWORD is reconciled
func (l *Local) reconcileAdminPassword() error {
	username := os.Getenv("GITEA_ADMIN_USERNAME")
	if username == "" {
		return fmt.Errorf("GITEA_ADMIN_USERNAME is not set")
	}
	password := os.Getenv("GITEA_ADMIN_PASSWORD")
	if password == "" {
		return fmt.Errorf("GITEA_ADMIN_PASSWORD is not set")
	}
	if err := l.initDB(); err != nil {
		return err
	}
	log.Printf("reconciling admin password for %s", username)

	if err := l.validateAdminPassword(username, password); err == nil {
		return nil
	}

	gitUser, err := user.GetUserByName(l.ctx, username)
	if err != nil {
		return fmt.Errorf("unable to get user %s: %w", username, err)
	}
	if err := gitUser.SetPassword(password); err != nil {
		return fmt.Errorf("unable to set password for user %s: %w", username, err)
	}
	gitUser.MustChangePassword = false
	if err := user.UpdateUserCols(l.ctx, gitUser, "passwd", "passwd_hash_algo", "salt", "must_change_password"); err != nil {
		return fmt.Errorf("unable to update user %s: %w", username, err)
	}
	log.Printf("successfully reconciled admin password for %s\n", username)
	return nil
}

func (l *Local) validateAdminPassword(username, password string) error {
	url := "http://localhost:3000"
	client := http.Client{}
	if os.Getenv("GITEA_TLS") != "" {
		url = "https://localhost:3000"
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		}
	}
	req, err := http.NewRequest("GET", url+"/api/v1/user", nil)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("unable to authenticate user: %s", resp.Status)
	}
	log.Printf("successfully authenticated user %s\n", username)
	return nil
}

func (l *Local) initDB() error {
	setting.InitCfgProvider("/data/gitea/conf/app.ini")
	// setting.LoadCommonSettings()
	// setting.MustInstalled()
	setting.LoadDBSetting()

	if setting.Database.Type == "" {
		err := fmt.Errorf(`Database settings are missing from the configuration file: %q
Ensure you are running in the correct environment or set the correct configuration file with -c.
If this is the intended configuration file complete the [database] section.`, setting.CustomConf)
		return fmt.Errorf("Failed to load database settings: %w", err)
	}
	if err := db.InitEngine(l.ctx); err != nil {
		return fmt.Errorf("unable to initialize the database using the configuration in %q. Error: %w", setting.CustomConf, err)
	}
	return nil
}
