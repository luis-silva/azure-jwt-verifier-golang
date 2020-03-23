/*******************************************************************************
 * Copyright 2018 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package oidc

import "github.com/luis-silva/azure-jwt-verifier-golang/discovery"

type Oidc struct {
	wellKnownUrl string
}

func (d Oidc) New() discovery.Discovery {
	d.wellKnownUrl = "/.well-known/openid-configuration"
	return d
}

func (d Oidc) GetWellKnownUrl() string {
	return d.wellKnownUrl
}
