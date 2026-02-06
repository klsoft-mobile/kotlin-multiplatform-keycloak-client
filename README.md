# KOTLIN-MULTIPLATFORM-KEYCLOAK-CLIENT

A Kotlin Multiplatform library that can be used to secure applications with Keycloak. It is typically used in conjunction with RESTful web service APIs.

See also:

 -  [YII2-JWT-AUTH](https://github.com/klsoft-web/yii2-jwt-auth) - The package provides a [Yii 2](https://www.yiiframework.com) authentication method based on a JWT token
 -  [YII2-KEYCLOAK-AUTHZ](https://github.com/klsoft-web/yii2-keycloak-authz) - The package provides Keycloak authorization for the web service APIs of [Yii 2](https://www.yiiframework.com)
 -  [YII3-JWT-AUTH](https://github.com/klsoft-web/yii3-jwt-auth) - The package provides a [Yii 3](https://yii3.yiiframework.com) authentication method based on a JWT token
 -  [YII3-KEYCLOAK-AUTHZ](https://github.com/klsoft-web/yii3-keycloak-authz) - The package provides Keycloak authorization for the web service APIs of [Yii 3](https://yii3.yiiframework.com)

## Supported platforms

 -  JVM
 -  Android
 -  iOS

## Installation

```kotlin
[versions]  
keycloakClient = "1.0.2"
serializationJson = "1.10.0"

[libraries]  
keycloak-client = { module = "io.github.klsoft-mobile.kotlin.multiplatform:keycloak-client", version.ref = "keycloakClient"}
kotlinx-serialization-json = { module = "org.jetbrains.kotlinx:kotlinx-serialization-json", version.ref = "serializationJson" }

implementation(libs.keycloak.client)
implementation(libs.kotlinx.serialization.json)
```

## Example of initializing a KeycloakClient

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

@Provides
fun provideKeycloakClient(): KeycloakClient = KeycloakClient.Builder()
    .setClientSecret("Keycloak client secret") //This is optional, but it is required when Keycloak 'Client authentication' is ON
    .build(  
        "http://mykeycloak.com/realms/myrealm",  
        "Keycloak client ID",  
        "http://mysite.com/login"); //Keycloak client redirect URI
```

## Example of creating an Authorization Code flow URL

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override fun loginUrl(): String {  
        return keycloakClient.createAuthorizationCodeLoginUrl() 
    }
}
```

## Example of creating an Implicit flow URL

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override fun loginUrl(): String {  
        return keycloakClient.createImplicitLoginUrl() 
    }
}
```

## Example of fetching a token using an Authorization Code

AuthScreen.kt

```kotlin
@Composable
private fun Content(
    loginUrl: String,
    codeReceived: (String) . Unit,
    innerPadding: PaddingValues

) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
    ) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context .
                WebView(context).apply {
                    settings.javaScriptEnabled = true
                    loadUrl(loginUrl)
                    webViewClient = object : WebViewClient() {
                        override fun onPageStarted(
                            view: WebView,
                            url: String,
                            favicon: Bitmap?
                        ) {
                            url.toUri().getQueryParameter("code")?.let { code ->
                                codeReceived(code)
                            }
                        }
                    }
                }
            }
        )
    }
}
```

AuthRepositoryImpl.kt

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun fetchTokenByAuthorizationCode(code: String): ApiResult<Tokens, ApiError> {  
        val responseResult = keycloakClient.fetchTokenByAuthorizationCode(code)
        if (responseResult.responseStatusCode == 200) {
            val data = responseResult.data
            if (data.containsKey(ACCESS_TOKEN) &&
                data.containsKey(REFRESH_TOKEN)) {
                return ApiResult.success(Tokens(
                    data.getValue(ACCESS_TOKEN).jsonPrimitive.content,
                    data.getValue(REFRESH_TOKEN).jsonPrimitive.content))
            }
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```

ApiResult.kt

```kotlin
sealed class ApiResult<out T, out E> {
    data class Success<T>(val result: T) : ApiResult<T, Nothing>()
    data class Error<E>(val error: E) : ApiResult<Nothing, E>()

    companion object {
        fun <T> success(value: T): Success<T> = Success(value)
        fun <E> error(error: E): Error<E> = Error(error)
    }
}
```

## Example of fetching a token using client credentials

This method can only be used by confidential clients. Make sure that both the **Client authentication** and **Service accounts roles** options are ON in Keycloak

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun fetchTokenByClientCredentials(): ApiResult<Tokens, ApiError> {  
        val responseResult = keycloakClient.fetchTokenByClientCredentials()
        if (responseResult.responseStatusCode == 200) {
            val data = responseResult.data
            if (data.containsKey(ACCESS_TOKEN))) {
                return ApiResult.success(Tokens(
                    data.getValue(ACCESS_TOKEN).jsonPrimitive.content,
                    null))
            }
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```

## Example of refreshing a token

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun refreshToken(refreshToken: String): ApiResult<Tokens, ApiError> {  
        val responseResult = keycloakClient.refreshToken(refreshToken)
        if (responseResult.responseStatusCode == 200) {
            val data = responseResult.data
            if (data.containsKey(ACCESS_TOKEN) &&
                data.containsKey(REFRESH_TOKEN)) {
                return ApiResult.success(Tokens(
                    data.getValue(ACCESS_TOKEN).jsonPrimitive.content,
                    data.getValue(REFRESH_TOKEN).jsonPrimitive.content))
            }
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```

## Example of fetching a Requesting Party Token using a permission ticket

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun fetchRequestingPartyTokenByPermissionTicket(
        accessToken: String, 
        permissionTicket: String): ApiResult<Tokens, ApiError> {  
        val responseResult = keycloakClient.fetchRequestingPartyTokenByPermissionTicket(
            accessToken, 
            permissionTicket)
            if (responseResult.responseStatusCode == 200) {
                val data = responseResult.data
                if (data.containsKey(ACCESS_TOKEN) &&
                    data.containsKey(REFRESH_TOKEN)) {
                    return ApiResult.success(Tokens(
                        data.getValue(ACCESS_TOKEN).jsonPrimitive.content,
                        data.getValue(REFRESH_TOKEN).jsonPrimitive.content))
            }
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```

## Example of fetching a Requesting Party Token by the client ID

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun fetchRequestingPartyTokenByClientId(accessToken: String): ApiResult<Tokens, ApiError> {  
        val responseResult = keycloakClient.fetchRequestingPartyTokenByClientId(accessToken)
        if (responseResult.responseStatusCode == 200) {
            val data = responseResult.data
            if (data.containsKey(ACCESS_TOKEN) &&
                data.containsKey(REFRESH_TOKEN)) {
                return ApiResult.success(Tokens(
                    data.getValue(ACCESS_TOKEN).jsonPrimitive.content,
                    data.getValue(REFRESH_TOKEN).jsonPrimitive.content))
            }
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```

## Example of fetching a user information

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun fetchUserInfo(accessToken: String): ApiResult<UserInfo, ApiError> {  
        val responseResult = keycloakClient.fetchUserInfo(accessToken)
        if (responseResult.responseStatusCode == 200) {
            val data = responseResult.data
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```

## Example of a logout

```kotlin
import klsoft.kotlin.multiplatform.keycloakclient.KeycloakClient

class AuthRepositoryImpl @Inject constructor(private val keycloakClient: KeycloakClient) : AuthRepository {

    override suspend fun logout(refreshToken: String): ApiResult<Unit, ApiError> {  
        val responseResult = keycloakClient.logout(refreshToken)
        if (responseResult.responseStatusCode == 204) {
            return ApiResult.success(Unit)
        } else if (responseResult.responseStatusCode == 401) {
            //Unauthorize
        } else {
            //Something got wrong
        }
    }
}
```
