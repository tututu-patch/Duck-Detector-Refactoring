#include <jni.h>

#include <string>

#include "nativeroot/common/codec.h"
#include "nativeroot/snapshot_builder.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_NativeRootNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jboolean skip_ksu_supercall
) {
    return to_jstring(
            env,
            duckdetector::nativeroot::encode_snapshot(
                    duckdetector::nativeroot::collect_snapshot(skip_ksu_supercall == JNI_TRUE)
            )
    );
}
