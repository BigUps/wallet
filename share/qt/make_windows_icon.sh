#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/Bigup.ico

convert ../../src/qt/res/icons/Bigup-16.png ../../src/qt/res/icons/Bigup-32.png ../../src/qt/res/icons/Bigup-48.png ${ICON_DST}
