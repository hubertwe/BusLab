#!/usr/bin/python

import re
from urlparse import *
from urllib import *
import subprocess


def isValid(type):
    if type == "video/webm; codecs=\"vp9\"":
        return True
    else:
        return False


def yt_url(video_url):
    video_id = parse_qs(urlparse(video_url).query)['v'][0]

    get_vars = urlparse(unquote(urlopen("http://www.youtube.com/get_video_info?video_id="+video_id).read()))

    table = str(get_vars).split("fmt");

    print table;


    #print len(get_vars["type"])
    #print len(get_vars["url"])
    #print get_vars["type"]

    validNumber=0;

    for (i, url) in enumerate(get_vars["url"]):
        pass
        #print get_vars["type"][i]
        #if isValid(get_vars["type"][i]):
         #   print "GOTCHA!"
          #  validNumber=i;


    return (get_vars["title"][0], get_vars["url"][validNumber] )



if __name__ == '__main__':
    (title, url) = yt_url("http://www.youtube.com/watch?v=eFr0XQAXWEE")
    print "Tytul: %s" % (title,)
    print "Link: %s" % (url,)
    urlretrieve (url, "video.webm")