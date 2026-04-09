#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>

// TIOCSCTTY may not be in Android NDK headers - define manually
#ifndef TIOCSCTTY
#define TIOCSCTTY 0x540E
#endif

static int open_slave_and_exec(const char *slave_name, const char *shell) {
    int slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave_fd < 0) return -1;

    setsid();
    ioctl(slave_fd, TIOCSCTTY, 0);

    dup2(slave_fd, 0);
    dup2(slave_fd, 1);
    dup2(slave_fd, 2);
    if (slave_fd > 2) close(slave_fd);

    execl(shell, shell, (char *) NULL);
    _exit(127);
    return -1;
}

JNIEXPORT jint JNICALL
Java_com_example_chatroom_participants_PtyNative_createPty(JNIEnv *env, jobject thiz, jstring jdevice, jstring jshell) {
    const char *device = (*env)->GetStringUTFChars(env, jdevice, NULL);
    const char *sh = (*env)->GetStringUTFChars(env, jshell, NULL);
    if (device == NULL || sh == NULL) {
        if (device) (*env)->ReleaseStringUTFChars(env, jdevice, device);
        if (sh) (*env)->ReleaseStringUTFChars(env, jshell, sh);
        return -1;
    }

    int master_fd = open(device, O_RDWR);
    if (master_fd < 0) {
        (*env)->ReleaseStringUTFChars(env, jdevice, device);
        (*env)->ReleaseStringUTFChars(env, jshell, sh);
        return -1;
    }

    if (grantpt(master_fd) < 0 || unlockpt(master_fd) < 0) {
        close(master_fd);
        (*env)->ReleaseStringUTFChars(env, jdevice, device);
        (*env)->ReleaseStringUTFChars(env, jshell, sh);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(master_fd);
        (*env)->ReleaseStringUTFChars(env, jdevice, device);
        (*env)->ReleaseStringUTFChars(env, jshell, sh);
        return -1;
    }

    if (pid == 0) {
        const char *slave_name = ptsname(master_fd);
        close(master_fd);
        if (slave_name) open_slave_and_exec(slave_name, sh);
        _exit(127);
    }

    (*env)->ReleaseStringUTFChars(env, jdevice, device);
    (*env)->ReleaseStringUTFChars(env, jshell, sh);
    return master_fd;
}

JNIEXPORT jint JNICALL
Java_com_example_chatroom_participants_PtyNative_readPty(JNIEnv *env, jobject thiz, jint fd, jbyteArray jbuf, jint timeoutMs) {
    jbyte *buf = (*env)->GetByteArrayElements(env, jbuf, NULL);
    if (buf == NULL) return -1;

    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) {
        (*env)->ReleaseByteArrayElements(env, jbuf, buf, 0);
        return ret;
    }

    ssize_t n = read(fd, buf, (size_t)(*env)->GetArrayLength(env, jbuf));
    (*env)->ReleaseByteArrayElements(env, jbuf, buf, 0);
    return n;
}

JNIEXPORT jint JNICALL
Java_com_example_chatroom_participants_PtyNative_writePty(JNIEnv *env, jobject thiz, jint fd, jstring jdata) {
    const char *data = (*env)->GetStringUTFChars(env, jdata, NULL);
    if (data == NULL) return -1;
    ssize_t n = write(fd, data, strlen(data));
    (*env)->ReleaseStringUTFChars(env, jdata, data);
    return n;
}

JNIEXPORT void JNICALL
Java_com_example_chatroom_participants_PtyNative_closePty(JNIEnv *env, jobject thiz, jint fd) {
    if (fd >= 0) close(fd);
}

JNIEXPORT jint JNICALL
Java_com_example_chatroom_participants_PtyNative_getPid(JNIEnv *env, jobject thiz, jint masterFd) {
    return (jint) getpid();
}

