// Generated by CoffeeScript 1.6.1

/* ABOUT
                       __  .__              ________ 
   ______ ____   _____/  |_|__| ____   ____/   __   \
  /  ___// __ \_/ ___\   __\  |/  _ \ /    \____    /
  \___ \\  ___/\  \___|  | |  (  <_> )   |  \ /    / 
 /____  >\___  >\___  >__| |__|\____/|___|  //____/  .co.uk
      \/     \/     \/                    \/         
                                              CoffeeGL
                                              Benjamin Blundell - ben@section9.co.uk
                                              http://www.section9.co.uk

This software is released under the MIT Licence. See LICENCE.txt for details


Framebuffer objects - reads the current active context from the exports and creates a FBO

Basic FBO with depth, linear filtering and RGBA with unsigned bytes

Remember, NPOT textures are support but not with repeats or mipmapping

- TODO
  * Depth options
*/


(function() {
  var CoffeeGLDebug, CoffeeGLError, Fbo, RGB, RGBA, TextureBase, Vec2, _ref, _ref1;

  _ref = require('./error'), CoffeeGLError = _ref.CoffeeGLError, CoffeeGLDebug = _ref.CoffeeGLDebug;

  _ref1 = require('./colour'), RGB = _ref1.RGB, RGBA = _ref1.RGBA;

  Vec2 = require('./math').Vec2;

  TextureBase = require('./texture').TextureBase;

  /*Fbo
  */


  Fbo = (function() {

    function Fbo(width, height, channels, datatype, depth) {
      var gl;
      this.width = width;
      this.height = height;
      this.channels = channels;
      this.datatype = datatype;
      this.depth = depth;
      gl = CoffeeGL.Context.gl;
      if (!((this.width != null) && (this.height != null))) {
        this.width = CoffeeGL.Context.width;
        this.height = CoffeeGL.Context.height;
      }
      if (this.channels == null) {
        this.channels = gl.RGBA;
      }
      if (this.datatype == null) {
        this.datatype = gl.UNSIGNED_BYTE;
      }
      if (this.depth == null) {
        this.depth = true;
      }
      this.framebuffer = gl.createFramebuffer();
      CoffeeGLDebug("Created an FBO  with dimensions: " + this.width + "," + this.height);
      this._build();
    }

    Fbo.prototype.resize = function(w, h) {
      if (w instanceof Vec2) {
        this.width = w.x;
        this.height = w.y;
      } else if ((w != null) && (h != null)) {
        this.width = w;
        this.height = h;
      } else {
        return this;
      }
      this._build();
      return this;
    };

    Fbo.prototype._build = function() {
      var gl, params;
      gl = CoffeeGL.Context.gl;
      gl.bindFramebuffer(gl.FRAMEBUFFER, this.framebuffer);
      if (this.texture == null) {
        params = {
          "min": gl.LINEAR,
          "max": gl.LINEAR,
          "wraps": gl.CLAMP_TO_EDGE,
          "wrapt": gl.CLAMP_TO_EDGE,
          "width": this.width,
          "height": this.height,
          "channels": this.channels,
          "datatype": this.datatype
        };
        this.texture = new TextureBase(params);
        this.texture.build();
      } else {
        this.texture.bind();
        gl.texImage2D(gl.TEXTURE_2D, 0, this.channels, this.width, this.height, 0, this.channels, this.datatype, null);
      }
      this.renderbuffer = gl.createRenderbuffer();
      gl.bindRenderbuffer(gl.RENDERBUFFER, this.renderbuffer);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.texture.texture, 0);
      if (this.depth) {
        gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, this.width, this.height);
        gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT, gl.RENDERBUFFER, this.renderbuffer);
      }
      gl.bindRenderbuffer(gl.RENDERBUFFER, null);
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      this.texture.unbind();
      if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) {
        return CoffeeGLError("Failed to Create Framebuffer!");
      }
    };

    Fbo.prototype.bind = function() {
      var gl;
      gl = CoffeeGL.Context.gl;
      gl.bindFramebuffer(gl.FRAMEBUFFER, this.framebuffer);
      gl.bindRenderbuffer(gl.RENDERBUFFER, this.renderbuffer);
      return gl.viewport(0, 0, this.width, this.height);
    };

    Fbo.prototype.unbind = function() {
      var gl;
      gl = CoffeeGL.Context.gl;
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      return gl.bindRenderbuffer(gl.RENDERBUFFER, null);
    };

    Fbo.prototype.clear = function(colour) {
      var gl;
      gl = CoffeeGL.Context.gl;
      if (colour == null) {
        gl.clearColor(0.0, 0.0, 0.0, 0.0);
      } else {
        if (colour instanceof RGBA) {
          gl.clearColor(colour.r, colour.g, colour.b, colour.a);
        } else if (colour instanceof RGB) {
          gl.clearColor(colour.r, colour.g, colour.b, 1.0);
        }
      }
      if (this.depth) {
        return gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
      } else {
        return gl.clear(gl.COLOR_BUFFER_BIT);
      }
    };

    Fbo.prototype.washUp = function() {
      var gl;
      gl = CoffeeGL.Context.gl;
      gl.deleteFramebuffer(this.framebuffer);
      gl.deleteRenderbuffer(this.renderbuffer);
      gl.deleteTexture(this.texture.texture);
      return this;
    };

    return Fbo;

  })();

  module.exports = {
    Fbo: Fbo
  };

}).call(this);
