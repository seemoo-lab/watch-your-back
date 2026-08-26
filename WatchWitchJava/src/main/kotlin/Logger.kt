package net.rec0de.android.watchwitch

object Logger {


    private const val GEN_LOG_LVL = 1
    private const val IKE_LOG_LVL = 4
    private const val IDS_LOG_LVL = 1
    private const val UTUN_LOG_LVL = 1
    private const val SHOES_LOG_LVL = 0
    private const val CMD_LOG_LVL = 0
    private const val SQL_LOG_LVL = 0

    fun setError(msg: String) {}

    fun log(msg: String, level: Int) {
        if(level <= GEN_LOG_LVL)
            Log.d("WatchWitch", msg)
    }

    fun logIDS(msg: String, level: Int) {
        if(level <= IDS_LOG_LVL)
            Log.d("WatchWitchIDS", msg)
    }

    fun logUTUN(msg: String, level: Int) {
        if(level <= UTUN_LOG_LVL)
            Log.d("WatchWitchAlloy", msg)
    }

    fun logShoes(msg: String, level: Int) {
        if(level <= SHOES_LOG_LVL)
            Log.d("WatchWitchShoes", msg)
    }

    fun logIKE(msg: String, level: Int) {
        if(level <= IKE_LOG_LVL)
            Log.d("WatchWitchIKE", msg)
    }

    fun logSQL(msg: String, level: Int) {
        if(level <= SQL_LOG_LVL)
            Log.d("WatchWitchSQL", msg)
    }

    fun logCmd(msg: String, level: Int) {
        if(level <= CMD_LOG_LVL)
            Log.d("WatchWitchCmd", msg)
    }
}