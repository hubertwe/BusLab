#!/usr/bin/python

import urlparse
import urllib
import re

def getFirstParam(videosString):
    return videosString.split('=')[0]

def getStremMapString(content):
    videos = content.split('url_encoded_fmt_stream_map=')[1]
    videos = videos.split('adaptive_fmts=')
    firstParam = getFirstParam(videos[0])
    videos = videos[0].split(',' + firstParam + '=')
    for i, video in enumerate(videos[1:]):
        videos[i+1] = firstParam + '=' + video
    return videos

def getAdaptiveFmtsString(content):
    videos = content.split('adaptive_fmts=')[1]
    videos = videos.split('url_encoded_fmt_stream_map=')
    firstParam = getFirstParam(videos[0])
    videos = videos[0].split(',' + firstParam + '=')
    for i, video in enumerate(videos[1:]):
        videos[i+1] = firstParam + '=' + video
    return videos


def getDecodedVideosString(content):
    streamMap = getStremMapString(content)
    adaptiveFtms = getAdaptiveFmtsString(content)
    return streamMap + adaptiveFtms

def getEncodedVideosString(content):
    pass

def isValidUrl(parsedUrl):
    return 'title' not in parsedUrl

def getEncodedVideos(content):
    pass

def getDecodedVideos(content):
    videos = list()
    videosString = getDecodedVideosString(content)
    for string in videosString:
        video = urlparse.parse_qs(string)
        if not isValidUrl(video):
            continue
        videos.append(video)
    return videos

def getUrl(video):
    url = video['url'][0]
    for param in video:
        if param == 'type' or param == ' codecs' or param == 'quality' or param == 'fallback_host' or param == 'url':
            continue
        url += '&' + param + '=' + video[param][0]
    return url

def getVideos(videoUrl):
    videoId = urlparse.parse_qs(urlparse.urlparse(videoUrl).query)['v'][0]
    content = urllib.urlopen("http://www.youtube.com/get_video_info?video_id="+videoId).read()
    content = urllib.unquote(content)
    content = urllib.unquote(content)
    content = urllib.unquote(content)
    decodedVideos = getDecodedVideos(content)
    return decodedVideos

def revers(signature):
    return signature[::-1]

def splice(signature, b):
    return list(signature[b:])

def swap(signature, b):
    sig = list(signature)
    temp = sig[0]
    sig[0] = sig[b % len(sig)]
    sig[b] = temp
    return sig

def decodeSignature(signature):
    sig = list(signature)
    sig = splice(sig, 2)
    sig = revers(sig)
    sig = splice(sig, 3)
    sig = revers(sig)
    sig = splice(sig, 3)
    sig = revers(sig)
    sig = swap(sig, 2)
    sig = ''.join(sig)
    return sig

def getType(video):
    return video['type'][0].split('/')[1]

def displayVideos(videos):
    print "Found " + str(len(videos)) + " video(s)"
    for i, video in enumerate(videos):
        print str(i+1) + '.'
        print 'Format: ' + getType(video)
        if 'quality' in video:
            print 'Quality: ' + video['quality'][0]
        if 'size' in video:
            print 'Size: ' + video['size'][0]
        if ' codecs' in video:
            print 'Codecs: ' + video[' codecs'][0]
        #print getUrl(video)
        print ''

def downloadVideo(link, name):
    print "Will download video and save as " + name
    file = urllib.URLopener()
    file.addheaders = [("User-agent", "lla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko)")]
    try: 
        file.retrieve(link, name)

    except IOError as e:
        print "Sorry but exception " + str(e[1]) + " was thrown. Something might gone wrong. Keep calm. "
    print "Done."

def askForDownload(videos):
    print "Which version you would like to download?"
    userInput = int(input("Give number between 1-" + str(len(videos)) + ": ")) - 1
    if (userInput < 0) or (userInput > len(videos)) :
       print "You've gave wrong number. Bailing out. Bye!"
       return
    downloadVideo(getUrl(videos[userInput]), 'video.'+ getType(videos[userInput]))
		


if __name__ == '__main__':
    videos = getVideos('http://www.youtube.com/watch?v=ALYateVoC7M')
    displayVideos(videos)
    askForDownload(videos)
