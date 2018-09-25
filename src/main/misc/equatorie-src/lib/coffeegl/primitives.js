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


Primitive Objects - holds support for the various buffers we need


 - TODO
  * Should we use mixins or similar for adding texture co-ords and colours?
  * There is probably a much better methodology here I think
  * draw should be implicit when a primitive is created / added methinx - but what of order? Placement? Z Depth?

Three uses a dynamic flag. potential there.
Need to bind functions so that if vertices are updated, we change the buffers! Should be possible
Also, we are assuming floats here too! Normally thats the case but not always I suspect!
Also GL_TRIANGLES as well (but thats probably for the best)
Context is taken from the actual context set in the object but what if we wish to change context?
When applying materials, we may need to AUTOGEN stuff - thats not a bad idea actually
*/


(function() {
  var Geometry, Line, Matrix4, Quad, RGB, RGBA, TriStrip, Triangle, TriangleMesh, Vec2, Vec3, Vec4, Vertex, type, _ref, _ref1,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  _ref = require('./colour'), RGBA = _ref.RGBA, RGB = _ref.RGB;

  _ref1 = require('./math'), Matrix4 = _ref1.Matrix4, Vec2 = _ref1.Vec2, Vec3 = _ref1.Vec3, Vec4 = _ref1.Vec4;

  /*Geometry
  */


  Geometry = (function() {

    function Geometry() {
      this.v = [];
      this.layout = "TRIANGLES";
      this.faces = [];
    }

    Geometry.prototype._addToNode = function(node) {
      node.geometry = this;
      return this;
    };

    return Geometry;

  })();

  /*Vertex
  */


  Vertex = (function() {

    function Vertex(p, c, n, t, tangent) {
      this.p = p;
      this.c = c;
      this.n = n;
      this.t = t;
      this.tangent = tangent;
      if (this.p == null) {
        this.p = new Vec3(0, 0, 0);
      }
    }

    Vertex.prototype.flatten = function() {
      var t;
      t = [];
      t.concat(this.p.flatten());
      if (this.c != null) {
        t.concat(this.c.flatten());
      }
      if (this.n != null) {
        t.concat(this.n.flatten());
      }
      if (this.t != null) {
        t.concat(this.t.flatten());
      }
      if (this.tangent != null) {
        t.concat(this.tangent.flatten());
      }
      return t;
    };

    return Vertex;

  })();

  type = function(obj) {
    var classToType, myClass, name, _i, _len, _ref2;
    if (obj === void 0 || obj === null) {
      return String(obj);
    }
    classToType = new Object;
    _ref2 = "Boolean Number String Function Array Date";
    for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
      name = _ref2[_i];
      RegExp.split(" ");
    }
    myClass = Object.prototype.toString.call(obj);
    if (myClass in classToType) {
      return classToType(myClass);
    }
    return 'object';
  };

  /*Triangle
  */


  Triangle = (function(_super) {

    __extends(Triangle, _super);

    function Triangle(p0, p1, p2, n) {
      this.n = n;
      Triangle.__super__.constructor.call(this);
      if ((p0 == null) || (p1 == null) || (p2 == null)) {
        this.v = [new Vertex(new Vec3(-1, -1, 0)), new Vertex(new Vec3(1, -1, 0)), new Vertex(new Vec3(0, 1, 0))];
      } else {
        this.v = [p0, p1, p2];
      }
      if (this.n == null) {
        this.computeFaceNormal();
      }
    }

    Triangle.prototype.flatten = function() {
      var t;
      t = [];
      t = t.concat(this.v[0].flatten());
      t = t.concat(this.v[1].flatten());
      t = t.concat(this.v[2].flatten());
      return t;
    };

    Triangle.prototype.computeFaceNormal = function() {
      var l0, l1;
      l0 = Vec3.sub(this.v[1].p, this.v[0].p);
      l1 = Vec3.sub(this.v[2].p, this.v[1].p);
      this.n = l0.cross(l1);
      this.n.normalize();
      return this;
    };

    return Triangle;

  })(Geometry);

  /*Quad
  */


  Quad = (function(_super) {

    __extends(Quad, _super);

    function Quad(p0, p1, p2, p3, n) {
      this.n = n;
      Quad.__super__.constructor.call(this);
      if ((p0 == null) || (p1 == null) || (p2 == null) || (p3 == null)) {
        p0 = new Vertex(new Vec3(-1, 1, 0), new RGBA(1.0, 1.0, 1.0, 1.0), new Vec3(0, 0, 1), new Vec2(0, 1));
        p1 = new Vertex(new Vec3(-1, -1, 0), new RGBA(1.0, 1.0, 1.0, 1.0), new Vec3(0, 0, 1), new Vec2(0, 0));
        p2 = new Vertex(new Vec3(1, 1, 0), new RGBA(1.0, 1.0, 1.0, 1.0), new Vec3(0, 0, 1), new Vec2(1, 1));
        p3 = new Vertex(new Vec3(1, -1, 0), new RGBA(1.0, 1.0, 1.0, 1.0), new Vec3(0, 0, 1), new Vec2(1, 0));
      }
      this.v = [p0, p1, p2, p3];
      this.layout = "TRIANGLE_STRIP";
      if (this.n == null) {
        this.computeFaceNormal();
      }
    }

    Quad.prototype.computeFaceNormal = function() {
      var l0, l1;
      l0 = Vec3.sub(this.v[1].p, this.v[0].p);
      l1 = Vec3.sub(this.v[2].p, this.v[1].p);
      this.n = l0.cross(l1);
      this.n.normalize();
      return this;
    };

    Quad.prototype.flatten = function() {
      var t;
      t = [];
      t = t.concat(this.v[0].flatten());
      t = t.concat(this.v[1].flatten());
      t = t.concat(this.v[2].flatten());
      t = t.concat(this.v[3].flatten());
      return t;
    };

    return Quad;

  })(Geometry);

  TriStrip = (function() {

    function TriStrip() {}

    return TriStrip;

  })();

  /*Line
  */


  Line = (function(_super) {

    __extends(Line, _super);

    function Line(s, e) {
      this.s = s;
      this.e = e;
      Line.__super__.constructor.call(this);
    }

    return Line;

  })(Geometry);

  /*TriangleMesh
  */


  TriangleMesh = (function(_super) {

    __extends(TriangleMesh, _super);

    function TriangleMesh(indexed) {
      this.indexed = indexed;
      TriangleMesh.__super__.constructor.call(this);
      this.v = [];
      this.faces = [];
      if ((this.indexed != null) === true) {
        this.indices = [];
      }
    }

    TriangleMesh.prototype.addTriangle = function(t) {
      var idx, p, ti, v, _i, _j, _len, _ref2;
      if (this.indices) {
        for (idx = _i = 0; _i <= 2; idx = ++_i) {
          p = this._findV(t.v[idx]);
          if (p === -1) {
            this.v.push(t.v[idx]);
            ti = this.v.length;
            ti -= 1;
            t.v[idx]._idx = ti;
            this.indices.push(ti);
          } else {
            this.indices.push(p);
          }
        }
      } else {
        _ref2 = t.v;
        for (_j = 0, _len = _ref2.length; _j < _len; _j++) {
          v = _ref2[_j];
          this.v.push(v);
        }
      }
      this.faces.push(t);
      return this;
    };

    TriangleMesh.prototype.addVertex = function(v) {
      this.v.push(v);
      return this;
    };

    TriangleMesh.prototype.addIndex = function(idx) {
      if (typeof indices !== "undefined" && indices !== null) {
        return indices.push(idx);
      }
    };

    /*
    addTriangleFromIndices : (indices) ->
      if @indices? 
        for v in indices
          if v >= @v.length
            console.log "CoffeeGL Warning - Adding indices past vertex range in TriangleMesh"
            return
          @indices.push v
      @
    
     addQuadFromIndices : (indices) ->
      if @indices? 
        for v in indices
          if v >= @v.length
            console.log "CoffeeGL Warning - Adding indices past vertex range in TriangleMesh"
            return
    
        @indices.push indices[0]
        @indices.push indices[1]
        @indices.push indices[2]
    
        @indices.push indices[0]
        @indices.push indices[2]
        @indices.push indices[3]
      @
    */


    TriangleMesh.prototype.addQuad = function(q) {
      var i, idx, p, ti, _i, _j, _k, _l, _len, _len1, _len2, _len3, _ref2, _ref3, _ref4, _ref5;
      if (this.indices) {
        _ref2 = [0, 1, 3];
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          idx = _ref2[_i];
          p = this._findV(q.v[idx]);
          if (p === -1) {
            this.v.push(q.v[idx]);
            ti = this.v.length;
            ti -= 1;
            q.v[idx]._idx = ti;
            this.indices.push(ti);
          } else {
            this.indices.push(p);
          }
        }
        _ref3 = [2, 3, 1];
        for (_j = 0, _len1 = _ref3.length; _j < _len1; _j++) {
          idx = _ref3[_j];
          p = this._findV(q.v[idx]);
          if (p === -1) {
            this.v.push(q.v[idx]);
            ti = this.v.length;
            ti -= 1;
            q.v[idx]._idx = ti;
            this.indices.push(ti);
          } else {
            this.indices.push(p);
          }
        }
      } else {
        _ref4 = [0, 1, 3];
        for (_k = 0, _len2 = _ref4.length; _k < _len2; _k++) {
          i = _ref4[_k];
          this.v.push(q.v[i]);
        }
        _ref5 = [2, 3, 1];
        for (_l = 0, _len3 = _ref5.length; _l < _len3; _l++) {
          i = _ref5[_l];
          this.v.push(q.v[i]);
        }
      }
      this.faces.push(new Triangle(q.v[0], q.v[1], q.v[3]));
      this.faces.push(new Triangle(q.v[2], q.v[3], q.v[1]));
      return this;
    };

    TriangleMesh.prototype._findV = function(vf) {
      var idx, _i, _ref2;
      if (vf._idx != null) {
        return vf._idx;
      }
      if (this.v.length > 0) {
        for (idx = _i = 0, _ref2 = this.v.length - 1; 0 <= _ref2 ? _i <= _ref2 : _i >= _ref2; idx = 0 <= _ref2 ? ++_i : --_i) {
          if (this.v[idx] === vf) {
            return idx;
          }
        }
      }
      return -1;
    };

    return TriangleMesh;

  })(Geometry);

  module.exports = {
    Geometry: Geometry,
    Vertex: Vertex,
    Triangle: Triangle,
    Quad: Quad,
    TriangleMesh: TriangleMesh
  };

}).call(this);