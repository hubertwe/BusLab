#!/usr/bin/python

import urlparse
import urllib

def getFileUrl(videoUrl):
    videoId = urlparse.parse_qs(urlparse.urlparse(videoUrl).query)['v'][0]
    content = urllib.urlopen("http://www.youtube.com/get_video_info?video_id="+videoId).read()
    '''Nie ogarniam czemu to unquote nie potrafi od razu wszystkiego zdekodowac, trzeba 3 razy odpalac'''
    content = urllib.unquote(content)
    content = urllib.unquote(content)
    content = urllib.unquote(content)

    allFiles = content.split('&url=')
    videoFiles = list()
    '''Pierwszy i ostatni element to nie linki'''
    for file in allFiles[1:-1]:
        '''Czy to sa poprawne linki?'''
        if getType(file)[0] == 'video':
            videoFiles.append(file)
            print file + '\n\n'
    '''Pierwszy element to nie link ostatni jest jakis dziwny zawsze,dlatego ich nie biore'''
    return videoFiles

'''Zwraca dwa elementy pierwszy:adio/video kolejny:rozszerzenie'''
def getType(url):
    encodedUrl = urlparse.parse_qs(url)
    '''Encoded url to mapa gdzie kazdemu kluczowi odpowiada lista jednoelementowa (troche to dziwne)'''
    typeParts = encodedUrl['type'][0].split('/')
    return (typeParts[0], typeParts[1])


if __name__ == '__main__':
    urls = getFileUrl('http://www.youtube.com/watch?v=iArR3mT2wo0')
    urllib.urlretrieve(urls[0], 'video.' + getType(urls[0])[1])