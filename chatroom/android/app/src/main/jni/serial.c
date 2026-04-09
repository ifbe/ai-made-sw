#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/select.h>

static speed_t baud_to_speed(int baud) {
    switch (baud) {
        case 9600:   return B9600;
        case 19200:  return B19200;
        case 38400:  return B38400;
        case 57600:  return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
        case 460800: return B460800;
        case 921600: return B921600;
        default:     return B115200;
    }
}

JNIEXPORT jint JNICALL
Java_com_example_chatroom_participants_SerialNative_openSerial(JNIEnv *env, jobject thiz, jstring jdevice, jint baud) {
    const char *device = (*env)->GetStringUTFChars(env, jdevice, NULL);
    if (device == NULL) return -1;

    int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    (*env)->ReleaseStringUTFChars(env, jdevice, device);
    if (fd < 0) return -1;

    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        close(fd);
        return -1;
    }

    cfmakeraw(&tty);
    cfsetispeed(&tty, baud_to_speed(baud));
    cfsetospeed(&tty, baud_to_speed(baud));
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 1;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    return fd;
}

JNIEXPORT jint JNICALL
Java_com_example_chatroom_participants_SerialNative_readSerial(JNIEnv *env, jobject thiz, jint fd, jbyteArray jbuf, jint timeoutMs) {
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
Java_com_example_chatroom_participants_SerialNative_writeSerial(JNIEnv *env, jobject thiz, jint fd, jstring jdata) {
    const char *data = (*env)->GetStringUTFChars(env, jdata, NULL);
    if (data == NULL) return -1;
    ssize_t n = write(fd, data, strlen(data));
    (*env)->ReleaseStringUTFChars(env, jdata, data);
    return n;
}

JNIEXPORT void JNICALL
Java_com_example_chatroom_participants_SerialNative_closeSerial(JNIEnv *env, jobject thiz, jint fd) {
    if (fd >= 0) close(fd);
}
