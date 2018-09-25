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


TODO - updating the pos and the matrix together :S tricksy
*/


(function() {
  var Matrix4, PointLight, RGB, RGBA, Vec2, Vec3, Vec4, _ref, _ref1;

  _ref = require('./math'), Matrix4 = _ref.Matrix4, Vec2 = _ref.Vec2, Vec3 = _ref.Vec3, Vec4 = _ref.Vec4;

  _ref1 = require('./colour'), RGB = _ref1.RGB, RGBA = _ref1.RGBA;

  /* PointLight
  */


  PointLight = (function() {

    function PointLight(pos, colour, specular, attenuation) {
      this.pos = pos;
      this.colour = colour;
      this.specular = specular;
      this.attenuation = attenuation;
      if (this.pos == null) {
        this.pos = new Vec3(1, 1, 1);
      }
      if (this.colour == null) {
        this.colour = RGB.WHITE();
      }
      if (this.specular == null) {
        this.specular = RGB.WHITE();
      }
      if (this.attenuation == null) {
        this.attenuation = 0.99;
      }
      this.shadow_casting = false;
    }

    PointLight.prototype._addToNode = function(node) {
      node.pointLights.push(this);
      node.numPointLights = node.pointLights.length;
      return this;
    };

    PointLight.prototype._removeFromNode = function(node) {
      node.pointLights.splice(node.pointLights.indexOf(this));
      node.numPointLights = node.pointLights.length;
      return this;
    };

    return PointLight;

  })();

  module.exports = {
    PointLight: PointLight
  };

}).call(this);