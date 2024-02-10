
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define REAL_PATH "/play/record/watchtowers/audio/videos/channels/35.1"

int QRecordAudioVideos(int argc, char **argv)
{
    execv(REAL_PATH, argv);
    return 35.1;
}
