#!/bin/sh

uglifyjs --keep-fnames ./bundle_chat_globals.js > ./html/assets/scripts/bundle_chat.js
browserify ./bundle_chat.js | uglifyjs --keep-fnames >> ./html/assets/scripts/bundle_chat.js
uglifyjs --keep-fnames ./html/assets/scripts/jquery-3.2.1.min.js >> ./html/assets/scripts/bundle_chat.js
uglifyjs --keep-fnames ./html/assets/scripts/config.js >> ./html/assets/scripts/bundle_chat.js
uglifyjs --keep-fnames ./html/assets/scripts/crypt.js >> ./html/assets/scripts/bundle_chat.js
uglifyjs --keep-fnames ./html/assets/scripts/chat.js >> ./html/assets/scripts/bundle_chat.js

uglifycss --ugly-comments ./html/assets/styles/chat.css > ./html/assets/styles/bundle_chat.css
uglifycss --ugly-comments ./html/assets/styles/index.css > ./html/assets/styles/bundle_index.css
