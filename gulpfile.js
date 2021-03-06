var fs = require('fs');
var gulp = require('gulp');
var del = require('del');
var es = require('event-stream');
var concat = require('gulp-concat');
var jshint = require('gulp-jshint');
var header = require('gulp-header');
var rename = require('gulp-rename');
var uglify = require('gulp-uglify');
var gutil = require('gulp-util');
var plumber = require('gulp-plumber');//To prevent pipe breaking caused by errors at 'watch'

var config = {
  pkg : JSON.parse(fs.readFileSync('./package.json')),
  banner:
      '/*!\n' +
      ' * <%= pkg.name %>\n' +
      ' * <%= pkg.homepage %>\n' +
      ' * Version: <%= pkg.version %> - <%= timestamp %>\n' +
      ' * License: <%= pkg.license %>\n' +
      ' */\n\n\n'
};

gulp.task('default', ['build']);
gulp.task('build', ['scripts']);

gulp.task('clean', function(cb) {
  del(['dist'], cb);
});

gulp.task('scripts', ['clean'], function() {

  var buildLib = function(){
    return gulp.src('src/ui-router-drf-auth.js')
      .pipe(plumber({
        errorHandler: handleError
      }))
      .pipe(jshint())
      .pipe(jshint.reporter('jshint-stylish'))
      .pipe(jshint.reporter('fail'));
  };

  return es.merge(buildLib())
    .pipe(plumber({
      errorHandler: handleError
    }))
    .pipe(concat('ui-router-drf-auth.js'))
    .pipe(header(config.banner, {
      timestamp: (new Date()).toISOString(), pkg: config.pkg
    }))
    .pipe(gulp.dest('dist'))
    .pipe(uglify({preserveComments: 'some'}))
    .pipe(rename('ui-router-drf-auth.min.js'))
    .pipe(gulp.dest('dist'));

});


var handleError = function (err) {
  console.log(err.toString());
  this.emit('end');
};
