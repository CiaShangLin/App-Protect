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
Java_com_shang_appprotect_AppProtect_shaKeyCompare(JNIEnv *env, jclass clazz,
                                                   jobject context_object) {
    const char *myKey = "A3584A3A4F16FFD4811ACF6258BE0EA6DD8C31C3";
    const char hexcode[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                            'E', 'F'};
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

    LOGD("sha1:%s", hex_sha);

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

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_shang_appprotect_AppProtect_findAppHookName(JNIEnv *env, jclass clazz, jobject context) {
    jclass Context_Class = env->GetObjectClass(context);
    jmethodID getPackageManager = env->GetMethodID(Context_Class, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(context, getPackageManager);

    jclass PackageManager_Class = env->GetObjectClass(packageManager);
    jmethodID getInstalledApplications = env->GetMethodID(PackageManager_Class,
                                                          "getInstalledApplications",
                                                          "(I)Ljava/util/List;");
    jobject applicationInfoList = env->CallObjectMethod(packageManager, getInstalledApplications,
                                                        0x00000080);

    jclass List_Class = env->GetObjectClass(applicationInfoList);
    jmethodID size_ID = env->GetMethodID(List_Class, "size", "()I");
    jmethodID get_ID = env->GetMethodID(List_Class, "get", "(I)Ljava/lang/Object;");

    jint size = env->CallIntMethod(applicationInfoList, size_ID);

    jboolean check = true;
    for (int i = 0; i < size; i++) {
        jobject application = env->CallObjectMethod(applicationInfoList, get_ID, i);
        jclass Application_Class = env->GetObjectClass(application);
        jfieldID packageName_ID = env->GetFieldID(Application_Class, "packageName",
                                                  "Ljava/lang/String;");
        jstring packageName = (jstring) env->GetObjectField(application, packageName_ID);

        const char *name = env->GetStringUTFChars(packageName, 0);

        //有裝xpose
        if (strcmp(name, "de.robv.android.xposed.installer") == 0) {
            check = false;
        }

        //有裝Cydia
        if (strcmp(name, "com.saurik.substrate") == 0) {
            check = false;
        }
        env->ReleaseStringUTFChars(packageName, name);
        env->DeleteLocalRef(application);
        env->DeleteLocalRef(Application_Class);
    }
    //LOGD("find:%d", find);
    env->DeleteLocalRef(context);
    env->DeleteLocalRef(Context_Class);
    env->DeleteLocalRef(packageManager);
    env->DeleteLocalRef(PackageManager_Class);
    env->DeleteLocalRef(applicationInfoList);
    env->DeleteLocalRef(List_Class);

    return check;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_shang_appprotect_AppProtect_applicationNameCheck(JNIEnv *env, jclass clazz,
                                                          jobject context) {
    jclass context_class = env->GetObjectClass(context);
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager",
                                          "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context, methodId);   //取得PackageManager

    methodId = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring) env->CallObjectMethod(context, methodId);   //取得PackageName

    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodId = env->GetMethodID(pack_manager_class, "getApplicationInfo",
                                "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");
    jobject package_info = env->CallObjectMethod(package_manager, methodId, package_name,
                                                 0);  //取得PackageInfo

    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID jfieldId = env->GetFieldID(package_info_class, "className", "Ljava/lang/String;");
    jstring className = (jstring) env->GetObjectField(package_info, jfieldId);


    jboolean app =
            strcmp(env->GetStringUTFChars(className, 0), "com.shang.appprotect.AppProtectApplication") == 0;

    env->DeleteLocalRef(context);
    env->DeleteLocalRef(context_class);
    env->DeleteLocalRef(package_manager);
    env->DeleteLocalRef(pack_manager_class);
    env->DeleteLocalRef(package_info);
    env->DeleteLocalRef(package_info_class);

    return app;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_shang_appprotect_AppProtect_isVA(JNIEnv *env, jclass clazz, jobject context) {
    const char *virtualPkgs[14] ={
            "com.bly.dkplat",                        //多开分身
            "dkplugin.pke.nnp",                      //當初複製來的就有了,但app可能消失了吧
            "com.by.chaos",                          //當初複製來的就有了,但app可能消失了吧
            "com.lbe.parallel",                      //LBE平行空間
            "com.excelliance.dualaid",               //双开助手
            "com.excelliance.dualaid.b64",           //双开助手 64bit
            "com.lody.virtual",                      //VirtualApp這個應該是libary
            "com.qihoo.magic",                       //分身大师
            "multi.parallel.dualspace.cloner",       //多開空間
            "com.polar.apps.dual.multi.accounts",    //Multi Accounts
            "com.lbe.parallel.intl",                //Parallel Space
            "com.lbe.parallel.intl.arm64",          //Parallel Space - 64Bit Support
            "com.applisto.appcloner",               //App Cloner
            "com.cloneapp.parallelspace.dualspace" //Clone App
    };

    bool isMultiApp = false;

    jclass contextClass = env->GetObjectClass(context);
    jmethodID filesDir = env->GetMethodID(contextClass, "getFilesDir", "()Ljava/io/File;");
    jobject file = env->CallObjectMethod(context, filesDir);

    jclass fileClass = env->FindClass("java/io/File");
    jmethodID getPath = env->GetMethodID(fileClass, "getPath", "()Ljava/lang/String;");

    jstring path = (jstring) env->CallObjectMethod(file, getPath);

    const char *cPath = env->GetStringUTFChars(path, NULL);

    if (cPath == NULL) {
        env->DeleteLocalRef(contextClass);
        env->DeleteLocalRef(file);
        env->DeleteLocalRef(fileClass);
        return false;
    }

    for (int i = 0; i < 14; i++) {
        if (strstr(cPath, virtualPkgs[i]) != NULL) {
            isMultiApp = true;
            env->DeleteLocalRef(contextClass);
            env->DeleteLocalRef(file);
            env->DeleteLocalRef(fileClass);
            env->ReleaseStringUTFChars(path, cPath);
            return isMultiApp;
        }
    }

    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(file);
    env->DeleteLocalRef(fileClass);
    env->ReleaseStringUTFChars(path, cPath);
    return isMultiApp;
}