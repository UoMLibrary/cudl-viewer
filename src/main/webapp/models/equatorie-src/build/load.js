// Generated by CoffeeScript 1.6.3
(function() {
  var CoffeeGL, LoadItem, LoadQueue, loadAssets, _loadAniso, _loadBackingShader, _loadBaseNormal, _loadBasic, _loadDepthShader, _loadEpicycleNormal, _loadFXAAShader, _loadLighting, _loadModel, _loadNeedleModel, _loadNeedleNormal, _loadPicking, _loadPlateNormal, _loadPointerNormal, _loadRimNormal, _loadSSAOShader, _loadStringShader;

  CoffeeGL = require('../lib/coffeegl/coffeegl').CoffeeGL;

  LoadItem = (function() {
    function LoadItem(func, userOnLoaded) {
      this.func = func;
      this.userOnLoaded = userOnLoaded;
    }

    LoadItem.prototype.loaded = function() {
      this.loader.itemCompleted(this);
      if (this.userOnLoaded != null) {
        return this.userOnLoaded();
      }
    };

    return LoadItem;

  })();

  LoadQueue = (function() {
    function LoadQueue(obj, onLoaded, onFinish) {
      this.obj = obj;
      this.onLoaded = onLoaded;
      this.onFinish = onFinish;
      this.items = [];
      this.completed_items = [];
      this.complete = new CoffeeGL.Signal();
      if (this.onFinish != null) {
        this.complete.add(onFinish, this);
      }
    }

    LoadQueue.prototype.itemCompleted = function(item) {
      this.completed_items.push(item);
      if (this.onLoaded != null) {
        this.onLoaded();
      }
      if (this.completed_items.length === this.items.length) {
        return this.complete.dispatch();
      }
    };

    LoadQueue.prototype.add = function(item) {
      item.obj = this.obj;
      item.loader = this;
      return this.items.push(item);
    };

    LoadQueue.prototype.start = function() {
      var item, _i, _len, _ref, _results;
      _ref = this.items;
      _results = [];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        item = _ref[_i];
        _results.push(item.func());
      }
      return _results;
    };

    return LoadQueue;

  })();

  _loadLighting = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/basic_lighting.glsl');
    r.get(function(data) {
      _this.obj.shader = new CoffeeGL.Shader(data, {
        "uAmbientLightingColor": "uAmbientLightingColor"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadAniso = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/anisotropic.glsl');
    r.get(function(data) {
      _this.obj.shader_aniso = new CoffeeGL.Shader(data, {
        "uAmbientLightingColor": "uAmbientLightingColor",
        "uSpecColour": "uSpecColour",
        "uSamplerNormal": "uSamplerNormal",
        "uAlphaX": "uAlphaX",
        "uAlphaY": "uAlphaY"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadModel = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../models/equatorie.js');
    r.get(function(data) {
      _this.obj.equatorie_model = new CoffeeGL.JSONModel(data, {
        onLoad: function() {
          return _this.loaded();
        }
      });
      return _this;
    });
    return this;
  });

  _loadBasic = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/basic.glsl');
    r.get(function(data) {
      _this.obj.shader_basic = new CoffeeGL.Shader(data, {
        "uColour": "uColour"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadPicking = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/picking.glsl');
    r.get(function(data) {
      _this.obj.shader_picker = new CoffeeGL.Shader(data, {
        "uPickingColour": "uPickingColour"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadStringShader = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/string.glsl');
    r.get(function(data) {
      _this.obj.shader_string = new CoffeeGL.Shader(data, {
        "uMatrices": "matrices",
        "uNumSegments": "segments"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadEpicycleNormal = new LoadItem(function() {
    var _this = this;
    this.obj.epicycle_normal = new CoffeeGL.Texture("../models/epicycle_NRM.jpg", {
      unit: 1
    }, function() {
      return _this.loaded();
    });
    return this;
  });

  _loadPlateNormal = new LoadItem(function() {
    var _this = this;
    this.obj.plate_normal = new CoffeeGL.Texture("../models/plate_NRM.jpg", {
      unit: 1
    }, function() {
      return _this.loaded();
    });
    return this;
  });

  _loadRimNormal = new LoadItem(function() {
    var _this = this;
    this.obj.rim_normal = new CoffeeGL.Texture("../models/ring_NRM.jpg", {
      unit: 1
    }, function() {
      return _this.loaded();
    });
    return this;
  });

  _loadPointerNormal = new LoadItem(function() {
    var _this = this;
    this.obj.pointer_normal = new CoffeeGL.Texture("../models/label_NRM.jpg", {
      unit: 1
    }, function() {
      return _this.loaded();
    });
    return this;
  });

  _loadBaseNormal = new LoadItem(function() {
    var _this = this;
    this.obj.base_normal = new CoffeeGL.Texture("../models/base_texture_NRM.jpg", {
      unit: 1
    }, function() {
      return _this.loaded();
    });
    return this;
  });

  _loadBackingShader = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/background.glsl');
    r.get(function(data) {
      _this.obj.shader_background = new CoffeeGL.Shader(data);
      return _this.loaded();
    });
    return this;
  });

  _loadDepthShader = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/depth.glsl');
    r.get(function(data) {
      _this.obj.shader_depth = new CoffeeGL.Shader(data);
      return _this.loaded();
    });
    return this;
  });

  _loadSSAOShader = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/ssao.glsl');
    r.get(function(data) {
      _this.obj.shader_ssao = new CoffeeGL.Shader(data, {
        "uSampler": "uSampler",
        "uSamplerDepth": "uSamplerDepth",
        "uRenderedTextureWidth": "uRenderedTextureWidth",
        "uRenderedTextureHeight": "uRenderedTextureHeight"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadFXAAShader = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../shaders/fxaa.glsl');
    r.get(function(data) {
      _this.obj.shader_fxaa = new CoffeeGL.Shader(data, {
        "uViewportSize": "viewportSize"
      });
      return _this.loaded();
    });
    return this;
  });

  _loadNeedleModel = new LoadItem(function() {
    var r,
      _this = this;
    r = new CoffeeGL.Request('../models/needle.js');
    r.get(function(data) {
      _this.obj.needle_model = new CoffeeGL.JSONModel(data, {
        onLoad: function() {
          return _this.loaded();
        }
      });
      return _this;
    });
    return this;
  });

  _loadNeedleNormal = new LoadItem(function() {
    var _this = this;
    this.obj.needle_normal = new CoffeeGL.Texture("../models/steel_NRM.jpg", {
      unit: 1
    }, function() {
      return _this.loaded();
    });
    return this;
  });

  loadAssets = function(obj, signal, signal_progress) {
    var a, b, lq;
    a = function() {
      return signal_progress.dispatch(this.completed_items.length / this.items.length);
    };
    b = function() {
      return signal.dispatch();
    };
    lq = new LoadQueue(obj, a, b);
    lq.add(_loadLighting);
    lq.add(_loadModel);
    lq.add(_loadBasic);
    lq.add(_loadPicking);
    lq.add(_loadAniso);
    lq.add(_loadEpicycleNormal);
    lq.add(_loadPlateNormal);
    lq.add(_loadRimNormal);
    lq.add(_loadPointerNormal);
    lq.add(_loadBaseNormal);
    lq.add(_loadBackingShader);
    lq.add(_loadStringShader);
    lq.add(_loadFXAAShader);
    lq.add(_loadNeedleModel);
    lq.add(_loadNeedleNormal);
    lq.add(_loadSSAOShader);
    lq.add(_loadDepthShader);
    lq.start();
    return this;
  };

  module.exports = {
    loadAssets: loadAssets
  };

}).call(this);