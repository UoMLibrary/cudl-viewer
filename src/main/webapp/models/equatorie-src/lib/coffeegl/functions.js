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
*/


(function() {
  var Matrix4, Vec2, Vec3, Vec4, precomputeTangent, rayCircleIntersection, rayPlaneIntersect, _precomputeTangent, _ref;

  _ref = require('./math'), Vec2 = _ref.Vec2, Vec3 = _ref.Vec3, Vec4 = _ref.Vec4, Matrix4 = _ref.Matrix4;

  /* rayPlaneIntersect
  */


  rayPlaneIntersect = function(plane_point, plane_normal, line_point, line_dir) {
    var den, num;
    num = Vec3.dot(plane_normal, Vec3.sub(plane_point, line_point));
    den = Vec3.dot(plane_normal, line_dir);
    return num / den;
  };

  /* precomputeTangent
  */


  precomputeTangent = function(a, b, c, na, nb, nc, ta, tb, tc) {
    return [_precomputeTangent(a, b, c, na, ta, tb, tc), _precomputeTangent(b, c, a, nb, tb, tc, ta), _precomputeTangent(c, a, b, nc, tc, ta, tb)];
  };

  _precomputeTangent = function(a, b, c, n, ta, tb, tc) {
    var alpha, binormal, binormal2, d, e, f, g, tangent, tx, ty, tz, ux, uy, uz;
    d = Vec3.sub(b, a);
    e = Vec3.sub(c, a);
    f = Vec2.sub(tb, ta);
    g = Vec2.sub(tc, ta);
    alpha = 1 / ((f.x * g.y) - (f.y * g.x));
    tx = alpha * (g.y * d.x + -f.y * e.x);
    ty = alpha * (g.y * d.y + -f.y * e.y);
    tz = alpha * (g.y * d.z + -f.y * e.z);
    ux = alpha * (-g.x * d.x + f.x * e.x);
    uy = alpha * (-g.x * d.y + f.x * e.y);
    uz = alpha * (-g.x * d.z + f.x * e.z);
    tangent = new Vec3(tx, ty, tz);
    binormal = new Vec3(ux, uy, uz);
    tangent = tangent.sub(Vec3.multScalar(n, Vec3.dot(n, tangent)));
    binormal2 = binormal.sub(Vec3.multScalar(n, Vec3.dot(n, binormal)));
    binormal2 = binormal2.sub(Vec3.multScalar(tangent, Vec3.dot(tangent, binormal)));
    tangent.normalize();
    binormal2.normalize();
    return tangent;
  };

  /* rayCircleIntersection
  */


  rayCircleIntersection = function(ray_start, ray_dir, circle_centre, circle_radius) {
    var a, b, c, d2, discriminant, f, r, t, t1, t2, v;
    f = CoffeeGL.Vec2.sub(ray_start, circle_centre);
    r = circle_radius;
    a = ray_dir.dot(ray_dir);
    b = 2 * f.dot(ray_dir);
    c = f.dot(f) - r * r;
    v = new CoffeeGL.Vec2();
    discriminant = b * b - 4 * a * c;
    if (discriminant !== 0) {
      discriminant = Math.sqrt(discriminant);
      t1 = (-b - discriminant) / (2 * a);
      t2 = (-b + discriminant) / (2 * a);
      t = t2;
      if (t2 < 0) {
        t = t1;
      }
      v.copyFrom(ray_start);
      d2 = CoffeeGL.Vec2.multScalar(ray_dir, t);
      v.add(d2);
    }
    return v;
  };

  module.exports = {
    rayPlaneIntersect: rayPlaneIntersect,
    rayCircleIntersection: rayCircleIntersection,
    precomputeTangent: precomputeTangent
  };

}).call(this);
