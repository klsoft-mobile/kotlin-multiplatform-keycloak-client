package klsoft.kotlin.multiplatform.keycloakclient

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.request.headers
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class KeycloakClient private constructor(
    realmUrl: String,
    private val clientId: String,
    private val redirectUri: String,
    private val clientSecret: String? = null
) {
    private var realmAuthorizationUrl: String = "$realmUrl/protocol/openid-connect/auth"
    private var realmTokenUrl: String = "$realmUrl/protocol/openid-connect/token"
    private var realmLogoutUrl: String = "$realmUrl/protocol/openid-connect/logout"
    private var realmUserInfoUrl: String = "$realmUrl/protocol/openid-connect/userinfo"

    private val client = HttpClient()

    class Builder {
        private var realmAuthorizationUrl: String? = null
        private var realmTokenUrl: String? = null
        private var realmLogoutUrl: String? = null
        private var realmUserInfoUrl: String? = null

        /**
         * @param realmAuthorizationUrl Realm authorization URL.
         *
         * @return Builder
         */
        fun setRealmAuthorizationUrl(realmAuthorizationUrl: String): Builder {
            this.realmAuthorizationUrl = realmAuthorizationUrl
            return this
        }

        /**
         * @param realmTokenUrl Realm token URL.
         *
         * @return Builder
         */
        fun setRealmTokenUrl(realmTokenUrl: String): Builder {
            this.realmTokenUrl = realmTokenUrl
            return this
        }

        /**
         * @param realmLogoutUrl Realm logout URL.
         *
         * @return Builder
         */
        fun setRealmLogoutUrl(realmLogoutUrl: String): Builder {
            this.realmLogoutUrl = realmLogoutUrl
            return this
        }

        /**
         * @param realmUserInfoUrl Realm userinfo URL.
         *
         * @return Builder
         */
        fun setRealmUserInfoUrl(realmUserInfoUrl: String): Builder {
            this.realmUserInfoUrl = realmUserInfoUrl
            return this
        }

        /**
         * @param realmUrl Keycloak realm URL
         * @param clientId Keycloak client ID
         * @param redirectUri Keycloak client redirect URI
         * @param clientSecret Keycloak client secret. This is optional, but it is required when Keycloak 'Client authentication' is ON
         *
         * @throws IllegalArgumentException
         */
        fun build(
            realmUrl: String,
            clientId: String,
            redirectUri: String,
            clientSecret: String? = null
        ): KeycloakClient {
            if (realmUrl.isBlank()) {
                throw IllegalArgumentException("The argument 'realmUrl' must not be empty");
            }

            if (clientId.isBlank()) {
                throw IllegalArgumentException("The argument 'clientId' must not be empty");
            }

            if (redirectUri.isBlank()) {
                throw IllegalArgumentException("The argument 'redirectUri' must not be empty");
            }

            val keycloakClient = KeycloakClient(realmUrl, clientId, redirectUri, clientSecret)
            keycloakClient.realmAuthorizationUrl = this.realmAuthorizationUrl ?: keycloakClient.realmAuthorizationUrl
            keycloakClient.realmTokenUrl = this.realmTokenUrl ?: keycloakClient.realmTokenUrl
            keycloakClient.realmLogoutUrl = this.realmLogoutUrl ?: keycloakClient.realmLogoutUrl
            keycloakClient.realmUserInfoUrl = this.realmUserInfoUrl ?: keycloakClient.realmUserInfoUrl
            return keycloakClient;
        }
    }


    /**
     * Create an Authorization Code flow URL for the Keycloak login form.
     *
     * @param scope
     *
     * @return A URL for the Keycloak login form
     *
     * @throws IllegalArgumentException
     */
    @OptIn(ExperimentalUuidApi::class)
    fun createAuthorizationCodeLoginUrl(scope: String = "openid"): String {
        if (scope.isBlank()) {
            throw IllegalArgumentException("The argument 'scope' must not be empty.")
        }
        return "$realmAuthorizationUrl?client_id=$clientId&response_type=code&scope=${scope.encodeURLParameter()}&redirect_uri=${redirectUri.encodeURLParameter()}&state=${Uuid.random()}&nonce=${Uuid.random()}"
    }

    /**
     * Create an Implicit flow URL for the Keycloak login form.
     *
     * @param scope
     *
     * @return A URL for the Keycloak login form
     *
     * @throws IllegalArgumentException
     */
    @OptIn(ExperimentalUuidApi::class)
    fun createImplicitLoginUrl(scope: String = "openid"): String {
        if (scope.isBlank()) {
            throw IllegalArgumentException("The argument 'scope' must not be empty.")
        }
        return "$realmAuthorizationUrl?client_id=$clientId&response_type=${"id_token token".encodeURLParameter()}&scope=${scope.encodeURLParameter()}&redirect_uri=${redirectUri.encodeURLParameter()}&state=${Uuid.random()}&nonce=${Uuid.random()}"
    }

    /**
     * Obtain a token using an Authorization Code.
     *
     * @param code An Authorization Code
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun getTokenByAuthorizationCode(code: String): ResponseResult {
        if (code.isBlank()) {
            throw IllegalArgumentException("The argument 'code' must not be empty.")
        }

        val response = client.submitForm(
            url = realmTokenUrl,
            formParameters = parameters {
                append("grant_type", "authorization_code")
                append("code", code)
                append("redirect_uri", redirectUri)
                append("client_id", clientId)
                if (clientSecret != null) {
                    append("client_secret", clientSecret)
                }
            }
        )
        return this.getResponseResult(response)
    }

    private suspend fun getResponseResult(response: HttpResponse): ResponseResult {
        val body = response.bodyAsText()
        return ResponseResult(
            response.status.value,
            if (body.isNotBlank()) Json.decodeFromString<JsonObject>(body) else JsonObject(mapOf())
        )
    }

    /**
     * Obtain a token using client credentials. This method can only be used by confidential clients. Make sure that both the 'Client authentication' and 'Service accounts roles' options are ON in Keycloak.
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun getTokenByClientCredentials(): ResponseResult {
        if (clientSecret.isNullOrBlank()) {
            throw IllegalArgumentException("The argument 'clientSecret' must not be empty.")
        }

        val response = client.submitForm(
            url = realmTokenUrl,
            formParameters = parameters {
                append("grant_type", "client_credentials")
                append("client_id", clientId)
                append("client_secret", clientSecret)
            }
        )
        return this.getResponseResult(response)
    }

    /**
     * Refresh a token.
     *
     * @param refreshToken
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun refreshToken(refreshToken: String): ResponseResult {
        if (refreshToken.isBlank()) {
            throw IllegalArgumentException("The argument 'refreshToken' must not be empty.")
        }

        val response = client.submitForm(
            url = realmTokenUrl,
            formParameters = parameters {
                append("grant_type", "refresh_token")
                append("refresh_token", refreshToken)
                append("client_id", clientId)
                if (clientSecret != null) {
                    append("client_secret", clientSecret)
                }
            }
        )
        return this.getResponseResult(response)
    }

    /**
     * Get a Requesting Party Token by a permission ticket.
     *
     * @param accessToken
     * @param permissionTicket
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun getRequestingPartyTokenByPermissionTicket(
        accessToken: String,
        permissionTicket: String
    ): ResponseResult {
        if (accessToken.isBlank()) {
            throw IllegalArgumentException("The argument 'accessToken' must not be empty.")
        }

        if (permissionTicket.isBlank()) {
            throw IllegalArgumentException("The argument 'permissionTicket' must not be empty.")
        }

        val response = client.submitForm(
            url = realmTokenUrl,
            formParameters = parameters {
                append("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
                append("ticket", permissionTicket)
            }
        ) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $accessToken")
            }
        }
        return this.getResponseResult(response)
    }

    /**
     * Get a Requesting Party Token by the client ID.
     *
     * @param accessToken
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun getRequestingPartyTokenByClientId(accessToken: String): ResponseResult {
        if (accessToken.isBlank()) {
            throw IllegalArgumentException("The argument 'accessToken' must not be empty.")
        }

        val response = client.submitForm(
            url = realmTokenUrl,
            formParameters = parameters {
                append("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
                append("audience", clientId)
            }
        ) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $accessToken")
            }
        }
        return this.getResponseResult(response)
    }

    /**
     * Get a userinfo by a bearer token.
     *
     * @param accessToken
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun getUserInfo(accessToken: String): ResponseResult {
        if (accessToken.isBlank()) {
            throw IllegalArgumentException("The argument 'accessToken' must not be empty.")
        }

        val response = client.get(realmUserInfoUrl) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $accessToken")
            }
        }
        return this.getResponseResult(response)
    }

    /**
     * Logout.
     *
     * @param refreshToken
     *
     * @return ResponseResult
     *
     * @throws IllegalArgumentException
     */
    suspend fun logout(refreshToken: String): ResponseResult {
        if (refreshToken.isBlank()) {
            throw IllegalArgumentException("The argument 'refreshToken' must not be empty.")
        }

        val response = client.submitForm(
            url = realmLogoutUrl,
            formParameters = parameters {
                append("refresh_token", refreshToken)
                append("client_id", clientId)
                if (clientSecret != null) {
                    append("client_secret", clientSecret)
                }
            }
        )
        return this.getResponseResult(response)
    }
}