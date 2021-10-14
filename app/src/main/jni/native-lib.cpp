#include <Jni.h>

#include <android/log.h>
#include <string.h>

#define TAG    "jni-log"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)

extern "C"
JNIEXPORT jstring JNICALL
Java_com_shang_appprotect_AppProtect_helloJni(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("Hello Jni");
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_shang_appprotect_AppProtect_shaKeyCompare(JNIEnv *env, jclass clazz,jobject context_object) {
    const char* myKey = "A3584A3A4F16FFD4811ACF6258BE0EA6DD8C31C3";
    const char hexcode[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    jclass context_class = env->GetObjectClass(context_object);

    //Java Reflection to get PackageManager
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager",
                                          "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context_object, methodId);
    if (package_manager == NULL) {
        LOGD("package_manager is NULL!!!");
        return NULL;
    }

    //Java Reflection to get package name
    methodId = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring) env->CallObjectMethod(context_object, methodId);
    if (package_name == NULL) {
        LOGD("package_name is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(context_class);

    //Java Reflection to get PackageInfo
    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo",
                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info = env->CallObjectMethod(package_manager, methodId, package_name, 0x40);
    if (package_info == NULL) {
        LOGD("getPackageInfo() is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(package_manager);

    //Get signature information
    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures",
                                       "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray) env->GetObjectField(package_info, fieldId);
    if (signature_object_array == NULL) {
        LOGD("signature is NULL!!!");
        return NULL;
    }
    jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
    env->DeleteLocalRef(package_info);

    //Convert signature information to Sha1
    jclass signature_class = env->GetObjectClass(signature_object);
    methodId = env->GetMethodID(signature_class, "toByteArray", "()[B");
    env->DeleteLocalRef(signature_class);
    jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodId);
    jclass byte_array_input_class = env->FindClass("java/io/ByteArrayInputStream");
    methodId = env->GetMethodID(byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = env->NewObject(byte_array_input_class, methodId, signature_byte);
    jclass certificate_factory_class = env->FindClass("java/security/cert/CertificateFactory");
    methodId = env->GetStaticMethodID(certificate_factory_class, "getInstance",
                                      "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = env->NewStringUTF("X.509");
    jobject cert_factory = env->CallStaticObjectMethod(certificate_factory_class, methodId,
                                                       x_509_jstring);
    methodId = env->GetMethodID(certificate_factory_class, "generateCertificate",
                                ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = env->CallObjectMethod(cert_factory, methodId, byte_array_input);
    env->DeleteLocalRef(certificate_factory_class);
    jclass x509_cert_class = env->GetObjectClass(x509_cert);
    methodId = env->GetMethodID(x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray) env->CallObjectMethod(x509_cert, methodId);
    env->DeleteLocalRef(x509_cert_class);
    jclass message_digest_class = env->FindClass("java/security/MessageDigest");
    methodId = env->GetStaticMethodID(message_digest_class, "getInstance",
                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = env->NewStringUTF("SHA1");
    jobject sha1_digest = env->CallStaticObjectMethod(message_digest_class, methodId, sha1_jstring);
    methodId = env->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) env->CallObjectMethod(sha1_digest, methodId, cert_byte);
    env->DeleteLocalRef(message_digest_class);

    //Convert to char
    jsize array_size = env->GetArrayLength(sha1_byte);
    jbyte *sha1 = env->GetByteArrayElements(sha1_byte, NULL);
    char *hex_sha = new char[array_size * 2 + 1];
    for (int i = 0; i < array_size; ++i) {
        hex_sha[2 * i] = hexcode[((unsigned char) sha1[i]) / 16];
        hex_sha[2 * i + 1] = hexcode[((unsigned char) sha1[i]) % 16];
    }
    hex_sha[array_size * 2] = '\0';

    LOGD("sha1:%s",hex_sha);

    return static_cast<jboolean>(strcmp(hex_sha, myKey) == 0);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_shang_appprotect_AppProtect_libSoCountCheck(JNIEnv *env, jclass clazz, jobject context) {
    jclass context_class = env->GetObjectClass(context);
    jmethodID getApplicationInfo = env->GetMethodID(context_class, "getApplicationInfo",
                                                    "()Landroid/content/pm/ApplicationInfo;");
    jobject applicationInfo = env->CallObjectMethod(context, getApplicationInfo);

    jclass applicationInfo_class = env->GetObjectClass(applicationInfo);
    jfieldID nativeLibraryDir_ID = env->GetFieldID(applicationInfo_class, "nativeLibraryDir",
                                                   "Ljava/lang/String;");
    jstring nativeLibraryDir = (jstring) env->GetObjectField(applicationInfo, nativeLibraryDir_ID);

    //LOGD("%s", Jstring2CStr(env, nativeLibraryDir));

    jclass file_class = env->FindClass("java/io/File");
    jmethodID file_init = env->GetMethodID(file_class, "<init>", "(Ljava/lang/String;)V");
    jobject file = env->NewObject(file_class, file_init, nativeLibraryDir);

    jmethodID getListFiles = env->GetMethodID(file_class, "listFiles", "()[Ljava/io/File;");
    jobjectArray listFiles = (jobjectArray) env->CallObjectMethod(file, getListFiles);

    jint length = env->GetArrayLength(listFiles);
//    LOGD("length=%d", length);

    jclass arrayList_class = env->FindClass("java/util/ArrayList");
    jmethodID arrayList_init = env->GetMethodID(arrayList_class, "<init>", "()V");
    jobject soLibList = env->NewObject(arrayList_class, arrayList_init, "");

    jmethodID add = env->GetMethodID(arrayList_class, "add", "(Ljava/lang/Object;)Z");

    //添加自己so檔的名稱
    env->CallBooleanMethod(soLibList, add, env->NewStringUTF("libnative-lib.so"));

    jmethodID contains = env->GetMethodID(arrayList_class, "contains", "(Ljava/lang/Object;)Z");

    for (int i = 0; i < length; i++) {
        jobject file = (jobject) env->GetObjectArrayElement(listFiles, i);
        jmethodID getName = env->GetMethodID(file_class, "getName", "()Ljava/lang/String;");
        jstring name = (jstring) env->CallObjectMethod(file, getName);
        if (env->CallBooleanMethod(soLibList, contains, name)) {
//            LOGD("TRUE:%s", Jstring2CStr(env, name));
        } else {
//            LOGD("FALSE:%s", Jstring2CStr(env, name));
            return JNI_FALSE;
        }
    }

    //lib的so檔數量
    if (length != 1) {
//        LOGD("FALSE lsngth:%d",length );
        return JNI_FALSE;
    }

    env->DeleteLocalRef(context_class);
    env->DeleteLocalRef(applicationInfo);
    env->DeleteLocalRef(applicationInfo_class);
    env->DeleteLocalRef(file_class);
    env->DeleteLocalRef(file);
    env->DeleteLocalRef(listFiles);

    return JNI_TRUE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_shang_appprotect_AppProtect_assetsCheck(JNIEnv *env, jclass clazz, jobject context) {
    jclass Context_Class = env->GetObjectClass(context);
    jmethodID getAssets_ID = env->GetMethodID(Context_Class, "getAssets",
                                              "()Landroid/content/res/AssetManager;");
    jobject assetManager = env->CallObjectMethod(context, getAssets_ID);

    jclass AssetManager_Class = env->GetObjectClass(assetManager);
    jmethodID list_ID = env->GetMethodID(AssetManager_Class, "list",
                                         "(Ljava/lang/String;)[Ljava/lang/String;");
    jobjectArray fileList = (jobjectArray) env->CallObjectMethod(assetManager, list_ID,
                                                                 env->NewStringUTF(""));

    jclass String_Class = env->FindClass("java/lang/String");
    jmethodID endsWith = env->GetMethodID(String_Class, "endsWith", "(Ljava/lang/String;)Z");

    jboolean ckeck = true;
    int length = env->GetArrayLength(fileList);
    for (int i = 0; i < length; i++) {
        jstring name = (jstring) env->GetObjectArrayElement(fileList, i);
        const char *Cname = env->GetStringUTFChars(name, 0);
        jboolean isSO = env->CallBooleanMethod(name, endsWith, env->NewStringUTF(".so"));

        if (isSO) {
            ckeck = false;
            LOGD("assetsCheck 找到奇怪的so檔");
        }
        if (strcmp(Cname, "cloudinject") == 0) {
            ckeck = false;
            LOGD("assetsCheck 找到cloudinject");
        }
        if (strcmp(Cname, "hook.apk") == 0) {
            ckeck = false;
            LOGD("assetsCheck 找到奇怪的apk檔");
        }
    }
    env->DeleteLocalRef(context);
    env->DeleteLocalRef(Context_Class);
    env->DeleteLocalRef(assetManager);
    env->DeleteLocalRef(AssetManager_Class);
    env->DeleteLocalRef(fileList);
    env->DeleteLocalRef(String_Class);

    return ckeck;
}