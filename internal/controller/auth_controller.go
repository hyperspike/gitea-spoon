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

package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/setting"
	service "code.gitea.io/gitea/services/auth"
	"code.gitea.io/gitea/services/auth/source/oauth2"

	hyperv1 "hyperspike.io/gitea-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
)

// AuthReconciler reconciles a Auth object
type AuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const authFinalizer = "auth.hyperspike.io/finalizer"

// +kubebuilder:rbac:groups=hyperspike.io,resources=auths,verbs=get;list;watch
// +kubebuilder:rbac:groups=hyperspike.io,resources=auths/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hyperspike.io,resources=auths/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Auth object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *AuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var auth hyperv1.Auth
	if err := r.Get(ctx, req.NamespacedName, &auth); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Auth resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Auth", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, err
	}

	if auth.Spec.Provider == "" {
		logger.Info("Auth provider not set. Ignoring")
		return ctrl.Result{}, nil
	}

	if auth.ObjectMeta.DeletionTimestamp.IsZero() {
		if !containsString(auth.ObjectMeta.Finalizers, authFinalizer) {
			if err := r.addSource(ctx, &auth); err != nil {
				logger.Error(err, "Failed to add source", "name", auth.Name)
				return ctrl.Result{}, err
			}
			auth.ObjectMeta.Finalizers = append(auth.ObjectMeta.Finalizers, authFinalizer)
			if err := r.Update(ctx, &auth); err != nil {
				logger.Error(err, "Failed to add finalizer", "name", auth.Name)
				return ctrl.Result{}, err
			}
		}
	} else {
		if containsString(auth.ObjectMeta.Finalizers, authFinalizer) {
			if err := r.deleteSource(ctx, &auth); err != nil {
				logger.Error(err, "Failed to delete source", "name", auth.Name)
				return ctrl.Result{}, err
			}
			auth.ObjectMeta.Finalizers = removeString(auth.ObjectMeta.Finalizers, authFinalizer)
			if err := r.Update(ctx, &auth); err != nil {
				logger.Error(err, "Failed to remove finalizer", "name", auth.Name)
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *AuthReconciler) addSource(ctx context.Context, auth *hyperv1.Auth) error {
	logger := log.FromContext(ctx)
	if err := initDB(ctx); err != nil {
		logger.Error(err, "Failed to initialize database")
		return err
	}
	clientID, err := r.getSecret(ctx, auth.Namespace, &auth.Spec.ClientID)
	if err != nil {
		logger.Error(err, "Failed to get clientID secret", "name", auth.Name)
		return err
	}
	clientSecret, err := r.getSecret(ctx, auth.Namespace, &auth.Spec.ClientSecret)
	if err != nil {
		logger.Error(err, "Failed to get clientSecret secret", "name", auth.Name)
		return err
	}
	src := &oauth2.Source{
		Provider:                      auth.Spec.Provider,
		ClientID:                      clientID,
		ClientSecret:                  clientSecret,
		Scopes:                        auth.Spec.Scopes,
		OpenIDConnectAutoDiscoveryURL: auth.Spec.AutoDiscoveryURL,
		GroupClaimName:                auth.Spec.GroupClaimName,
		CustomURLMapping:              nil,
	}
	logger.Info("Creating source", "name", auth.Name, "provider", src.Provider)
	err = model.CreateSource(ctx, &model.Source{
		Type:     model.OAuth2,
		Name:     auth.Name,
		IsActive: true,
		Cfg:      src,
	})
	if err != nil {
		logger.Error(err, "Failed to create auth source", "name", auth.Name)
		return err
	}
	return nil
}

func (r *AuthReconciler) deleteSource(ctx context.Context, auth *hyperv1.Auth) error {
	logger := log.FromContext(ctx)
	if err := initDB(ctx); err != nil {
		logger.Error(err, "Failed to initialize database", "name", auth.Name)
		return err
	}
	source, err := model.GetSourceByID(ctx, int64(1))
	if err != nil {
		return err
	}

	return service.DeleteSource(ctx, source)
}

func initDB(ctx context.Context) error {
	logger := log.FromContext(ctx)
	setting.InitCfgProvider("/data/gitea/conf/app.ini")
	//setting.LoadCommonSettings()
	//setting.MustInstalled()
	setting.LoadDBSetting()

	if setting.Database.Type == "" {
		err := fmt.Errorf(`Database settings are missing from the configuration file: %q
Ensure you are running in the correct environment or set the correct configuration file with -c.
If this is the intended configuration file complete the [database] section.`, setting.CustomConf)
		logger.Error(err, "Failed to load database settings")
		return err
	}
	if err := db.InitEngine(ctx); err != nil {
		return fmt.Errorf("unable to initialize the database using the configuration in %q. Error: %w", setting.CustomConf, err)
	}
	return nil
}

// A utility function to get a secret via a secretkeyref/secretkeyselector
func (r *AuthReconciler) getSecret(ctx context.Context, ns string, secretKeyRef *corev1.SecretKeySelector) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: ns,
		Name:      secretKeyRef.Name,
	}, secret); err != nil {
		return "", err
	}
	return string(secret.Data[secretKeyRef.Key]), nil
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	for i, v := range slice {
		if v == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Uncomment the following line adding a pointer to an instance of the controlled resource as an argument
		For(&hyperv1.Auth{}).
		Complete(r)
}
