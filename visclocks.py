#!/usr/bin/python
#
# Copyright (C) 2012  Miroslav Lichvar <mlichvar@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys, pygame
import collections
import math

freq_file = open(sys.argv[1], 'r')
offset_file = open(sys.argv[2], 'r')
delay_file = open(sys.argv[3], 'r')

(maxx, maxy) = (640, 480)

pygame.init()
window = pygame.display.set_mode((maxx, maxy))
font = pygame.font.SysFont("monospace", 12)

pygame.time.set_timer(pygame.USEREVENT, 1000 / 30)

white = (255, 255, 255)
black = (0, 0, 0)
blue = (50, 50, 255)
lightblue = (150, 150, 255)
red = (255, 0, 0)
green = (0, 255, 0)

freqs = collections.deque()
offsets = collections.deque()
delays = []

freq_avg = 0.0
time = -1
xscale = 2e-1
yscale = 1e6
frame_skip = 10

offset_rms = [ 0, 0, 0, 0 ]
offset_lock = 0
delays_shown = 3
eof = False
paused = False
game_mode = False

while True:
    line1 = delay_file.readline()
    line2 = delay_file.readline()
    if line1 == "" or line2 == "":
        break
    line1 = line1.split()
    line2 = line2.split()
    if line1[2] != "1" or line2[1] != "1" or line1[1] != line2[2]:
        continue
    delay1 = float(line1[3])
    delay2 = float(line2[3])
    delays.append((int(line1[1]), int(float(line2[0])), (delay1 - delay2) / 2, (delay1 + delay2) / 2))
delay_file.close()

while True:
    event = pygame.event.wait()
    if event.type == pygame.QUIT:
        break
    if event.type == pygame.KEYDOWN:
        if event.key == pygame.K_SPACE or event.key == pygame.K_p:
            paused = not paused
        elif event.key == pygame.K_q:
            break
        elif event.key == pygame.K_g:
            game_mode = not game_mode
            pygame.event.set_grab(game_mode)
            pygame.mouse.set_visible(not game_mode)
        elif event.key == pygame.K_l:
            offset_lock += 1
            offset_lock %= len(offset_rms)
            delays_shown = offset_lock + 1
            if delays_shown == 1:
                delays_shown = 3
        elif event.key == pygame.K_PAGEUP:
            frame_skip *= 2
        elif event.key == pygame.K_PAGEDOWN:
            frame_skip /= 2
            if frame_skip <= 5:
                frame_skip = 5
        elif event.key == pygame.K_UP:
            yscale *= 2
        elif event.key == pygame.K_DOWN:
            yscale /= 2
        elif event.key == pygame.K_LEFT:
            xscale *= 2
        elif event.key == pygame.K_RIGHT:
            xscale /= 2
    elif event.type == pygame.MOUSEMOTION:
        rel = pygame.mouse.get_rel()
        if game_mode and rel != (0, 0):
            freq_avg += rel[1] / 1e9

    pygame.event.clear(pygame.USEREVENT)

    if event.type != pygame.USEREVENT or paused:
        continue

    while not eof:
        histsize = maxx / xscale

        freq = freq_file.readline()
        if freq == "":
            eof = True
            break
        freqs.appendleft(float(freq))
        while len(freqs) > histsize:
            freqs.pop()

        offset = offset_file.readline()
        if offset == "":
            eof = True
            break
        offsets.appendleft(map(float, offset.split()))
        while len(offsets) > histsize:
            offsets.pop()

        if not game_mode:
            freq_avg += 0.001 * (freqs[0] - freq_avg)
        else:
            buttons = pygame.mouse.get_pressed()
            if buttons == (1, 0, 0):
                slew = 1e-6
            elif buttons == (0, 0, 1):
                slew = -1e-6
            else:
                slew = 0.0
            offsets[0][0] = offsets[1][0] - (freq_avg - freqs[0] + slew)

        offset_rms = [r + 0.001 * (o * o - r) for r, o in zip(offset_rms, offsets[0])]

        time += 1
        if time % frame_skip == 0:
            break

    if len(offsets) == 0:
        continue

    window.fill(black)
    last_off = []
    x = maxx
    y = maxy / 2 + offsets[0][offset_lock] * yscale

    def get_delays(time):
        index = len(delays) - 1
        while time >= 0 and index >= 0:
            while delays[index][1] > time:
                index -= 1
            while delays[index][1] == time and delays[index][0] != delays_shown:
                index -= 1
            if delays[index][1] != time:
                yield (False, 0, 0)
            else:
                yield (True, delays[index][2], delays[index][3])
            time -= 1


    for freq, offset, (delay_valid, delay_center, delay_size) in zip(freqs, offsets, get_delays(time)):
        x -= xscale
        y -= (freq - freq_avg) * yscale
        if int(x + xscale) != int(x):
            for i, (off, col) in enumerate(zip(offset, [white, red, green, blue])):
                oy = y - off * yscale
                if len(last_off) > i:
                    pygame.draw.aaline(window, col, last_off[i], (x, oy))
                else:
                    last_off.append(())
                last_off[i] = (x, oy)
                if game_mode:
                    break

        if delay_valid:
            pygame.draw.line(window, blue, (x, y - (delay_center - delay_size) * yscale), (x, y - (delay_center + delay_size) * yscale))
            pygame.draw.line(window, lightblue, (x - 3, y - delay_center * yscale), (x + 3, y - delay_center * yscale))

    window.blit(font.render("time = %d rms = %s xscale = %.1e yscale = %.1e" % (time, ["%1.6f" % math.sqrt(o) for o in offset_rms], xscale, yscale), False, white, black), (5, 0))
    window.blit(font.render("q:Quit  p:Pause  PgDn:Slow down  PgUp:Speed up  g:Game mode  l:Switch lock  Arrows:Scale", False, white, black), (5, maxy - 15))
    pygame.display.flip()

    #pygame.image.save(window, "visclocks%06d.png" % time)

freq_file.close()
offset_file.close()
