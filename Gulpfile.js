'use strict';

const gulp = require('gulp');
const plugins = require('gulp-load-plugins')();

var moduleName = 'aws-sign-web';

// Build the minified version
function uglify() {
    return gulp.src('./' + moduleName + '.js')
        .pipe(plugins.uglify({output: {comments: /Copyright/}}))
        .pipe(plugins.rename(moduleName + '.min.js'))
        .pipe(gulp.dest('.'));
}

exports.uglify = uglify;
exports.default = exports.uglify;
