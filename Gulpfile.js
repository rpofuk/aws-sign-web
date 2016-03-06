'use strict';

var gulp = require('gulp');
var plugins = require('gulp-load-plugins')();

gulp.task('dist-min', function () {
    return gulp.src('src/aws-sign-web.js')
        .pipe(plugins.uglify({preserveComments: 'license'}))
        .pipe(plugins.rename('aws-sign-web.min.js'))
        .pipe(gulp.dest('dist'));
});

gulp.task('dist-normal', function () {
    return gulp.src('src/aws-sign-web.js')
        .pipe(gulp.dest('dist'));
});

gulp.task('dist', ['dist-min', 'dist-normal']);
gulp.task('default', ['dist']);