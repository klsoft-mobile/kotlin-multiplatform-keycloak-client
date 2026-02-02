package klsoft.kotlin.multiplatform.keycloakclient

import kotlinx.serialization.json.JsonObject

/**
 * @param responseStatusCode
 * @param data
 */
data class ResponseResult(
    val responseStatusCode: Int,
    val data: JsonObject
)