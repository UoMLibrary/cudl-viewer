// Generated by CoffeeScript 1.6.3
(function() {
  var CoffeeGL, EquatorieString,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  CoffeeGL = require('../lib/coffeegl/coffeegl').CoffeeGL;

  EquatorieString = (function(_super) {
    __extends(EquatorieString, _super);

    function EquatorieString(length, thickness, segments) {
      var geom, i, vert, _i, _j, _len, _ref, _ref1;
      this.length = length;
      this.thickness = thickness;
      this.segments = segments;
      EquatorieString.__super__.constructor.call(this);
      geom = new CoffeeGL.Shapes.Cylinder(this.thickness, 24, this.segments, this.length);
      _ref = geom.v;
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        vert = _ref[_i];
        vert.p.y = 0.0;
      }
      this.add(geom);
      this.matrices = [];
      for (i = _j = 0, _ref1 = this.segments; 0 <= _ref1 ? _j <= _ref1 : _j >= _ref1; i = 0 <= _ref1 ? ++_j : --_j) {
        this.matrices.push(new CoffeeGL.Matrix4());
      }
    }

    EquatorieString.prototype.update = function(data) {
      var i, phys, tmatrix, tq, _i, _ref, _results;
      _results = [];
      for (i = _i = 0, _ref = this.segments; 0 <= _ref ? _i <= _ref : _i >= _ref; i = 0 <= _ref ? ++_i : --_i) {
        phys = data.segments[i];
        this.matrices[i].identity();
        tq = new CoffeeGL.Quaternion(new CoffeeGL.Vec3(phys.q[0], phys.q[1], phys.q[2]), phys.q[3]);
        tmatrix = tq.getMatrix4();
        tmatrix.setPos(new CoffeeGL.Vec3(phys.x, phys.y, phys.z));
        _results.push(this.matrices[i].copyFrom(tmatrix));
      }
      return _results;
    };

    return EquatorieString;

  })(CoffeeGL.Node);

  module.exports = {
    EquatorieString: EquatorieString
  };

}).call(this);
