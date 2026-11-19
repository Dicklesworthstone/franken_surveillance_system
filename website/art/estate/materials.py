"""Materials for Alder House. Runs inside Blender (Cycles)."""
import math
import pathlib

import bpy

ASSETS = pathlib.Path(__file__).resolve().parent / "assets"


def _new(name):
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    nodes, links = mat.node_tree.nodes, mat.node_tree.links
    bsdf = nodes.get("Principled BSDF")
    return mat, nodes, links, bsdf


def _set(bsdf, **values):
    names = {"color": "Base Color", "rough": "Roughness", "metal": "Metallic", "ior": "IOR",
             "emit": "Emission Color", "strength": "Emission Strength", "transmission": "Transmission Weight",
             "coat": "Coat Weight", "alpha": "Alpha", "spec": "Specular IOR Level", "sheen": "Sheen Weight"}
    for key, value in values.items():
        socket = bsdf.inputs[names[key]]
        socket.default_value = (*value, 1.0) if isinstance(value, tuple) and len(value) == 3 else value


def paint(name, color, rough=0.5, bump=0.0, bump_scale=60.0, coat=0.0, metal=0.0):
    """A painted or plain surface with optional fine surface noise."""
    mat, nodes, links, bsdf = _new(name)
    _set(bsdf, color=color, rough=rough, coat=coat, metal=metal)
    if bump:
        noise = nodes.new("ShaderNodeTexNoise")
        noise.inputs["Scale"].default_value = bump_scale
        noise.inputs["Detail"].default_value = 6.0
        b = nodes.new("ShaderNodeBump")
        b.inputs["Strength"].default_value = bump
        b.inputs["Distance"].default_value = 0.004
        links.new(noise.outputs["Fac"], b.inputs["Height"])
        links.new(b.outputs["Normal"], bsdf.inputs["Normal"])
        ramp = nodes.new("ShaderNodeMapRange")
        ramp.inputs["To Min"].default_value = max(0.0, rough - 0.08)
        ramp.inputs["To Max"].default_value = min(1.0, rough + 0.1)
        links.new(noise.outputs["Fac"], ramp.inputs["Value"])
        links.new(ramp.outputs["Result"], bsdf.inputs["Roughness"])
    return mat


def pbr(name, slug, size, tint=None, value=1.0, bump=1.0, rough_add=0.0):
    """A Poly Haven texture set mapped so one repeat covers `size` metres."""
    mat, nodes, links, bsdf = _new(name)
    coord = nodes.new("ShaderNodeTexCoord")
    mapping = nodes.new("ShaderNodeMapping")
    mapping.inputs["Scale"].default_value = (1.0 / size, 1.0 / size, 1.0)
    links.new(coord.outputs["UV"], mapping.inputs["Vector"])
    folder = ASSETS / "textures" / slug

    def image(file, colorspace):
        node = nodes.new("ShaderNodeTexImage")
        node.image = bpy.data.images.load(str(folder / file), check_existing=True)
        node.image.colorspace_settings.name = colorspace
        links.new(mapping.outputs["Vector"], node.inputs["Vector"])
        return node

    diffuse = image("Diffuse.jpg", "sRGB")
    out = diffuse.outputs["Color"]
    if tint or value != 1.0:
        mix = nodes.new("ShaderNodeMix")
        mix.data_type = "RGBA"
        mix.blend_type = "MULTIPLY"
        mix.inputs["Factor"].default_value = 1.0
        t = tint or (1.0, 1.0, 1.0)
        mix.inputs["B"].default_value = (t[0] * value, t[1] * value, t[2] * value, 1.0)
        links.new(out, mix.inputs["A"])
        out = mix.outputs["Result"]
    links.new(out, bsdf.inputs["Base Color"])
    if (folder / "Rough.jpg").exists():
        rough = image("Rough.jpg", "Non-Color")
        if rough_add:
            add = nodes.new("ShaderNodeMath")
            add.operation = "ADD"
            add.use_clamp = True
            add.inputs[1].default_value = rough_add
            links.new(rough.outputs["Color"], add.inputs[0])
            links.new(add.outputs["Value"], bsdf.inputs["Roughness"])
        else:
            links.new(rough.outputs["Color"], bsdf.inputs["Roughness"])
    if (folder / "nor_gl.jpg").exists():
        normal = image("nor_gl.jpg", "Non-Color")
        nmap = nodes.new("ShaderNodeNormalMap")
        nmap.inputs["Strength"].default_value = bump
        links.new(normal.outputs["Color"], nmap.inputs["Color"])
        links.new(nmap.outputs["Normal"], bsdf.inputs["Normal"])
    return mat


def glass(name, tint=(0.93, 0.96, 0.95), rough=0.0):
    """Thin architectural glass: mirror-like at grazing angles, clear face on."""
    mat, nodes, links, bsdf = _new(name)
    nodes.remove(bsdf)
    out = nodes["Material Output"]
    fresnel = nodes.new("ShaderNodeFresnel")
    fresnel.inputs["IOR"].default_value = 1.52
    clear = nodes.new("ShaderNodeBsdfTransparent")
    clear.inputs["Color"].default_value = (*tint, 1.0)
    shine = nodes.new("ShaderNodeBsdfGlossy")
    shine.inputs["Roughness"].default_value = rough
    mix = nodes.new("ShaderNodeMixShader")
    links.new(fresnel.outputs["Fac"], mix.inputs["Fac"])
    links.new(clear.outputs["BSDF"], mix.inputs[1])
    links.new(shine.outputs["BSDF"], mix.inputs[2])
    links.new(mix.outputs["Shader"], out.inputs["Surface"])
    return mat


def emitter(name, color, strength):
    mat, nodes, links, bsdf = _new(name)
    _set(bsdf, color=(0.0, 0.0, 0.0), emit=color, strength=strength)
    return mat


def fabric(name, color, translucency=0.5):
    """Curtain cloth that lets some light through."""
    mat, nodes, links, bsdf = _new(name)
    nodes.remove(bsdf)
    out = nodes["Material Output"]
    diffuse = nodes.new("ShaderNodeBsdfDiffuse")
    diffuse.inputs["Color"].default_value = (*color, 1.0)
    through = nodes.new("ShaderNodeBsdfTranslucent")
    through.inputs["Color"].default_value = (*color, 1.0)
    mix = nodes.new("ShaderNodeMixShader")
    mix.inputs["Fac"].default_value = translucency
    links.new(diffuse.outputs["BSDF"], mix.inputs[1])
    links.new(through.outputs["BSDF"], mix.inputs[2])
    links.new(mix.outputs["Shader"], out.inputs["Surface"])
    return mat


def interior(name, slug, yaw_deg, strength, tint=(1.0, 1.0, 1.0), hfov_deg=74.0):
    """A furnished room seen through a window.

    The backdrop plane shows a rectilinear view into an indoor CC0 panorama.
    Its UVs run 0..1 across the plane; yaw picks which way the view faces.
    """
    mat, nodes, links, bsdf = _new(name)
    nodes.remove(bsdf)
    out = nodes["Material Output"]
    coord = nodes.new("ShaderNodeTexCoord")
    split = nodes.new("ShaderNodeSeparateXYZ")
    links.new(coord.outputs["UV"], split.inputs["Vector"])
    half = math.tan(math.radians(hfov_deg) / 2)

    def centred(socket, scale):
        node = nodes.new("ShaderNodeMath")
        node.operation = "MULTIPLY_ADD"
        node.inputs[1].default_value = 2.0 * scale
        node.inputs[2].default_value = -scale
        links.new(socket, node.inputs[0])
        return node.outputs["Value"]

    direction = nodes.new("ShaderNodeCombineXYZ")
    links.new(centred(split.outputs["X"], half), direction.inputs["X"])
    direction.inputs["Y"].default_value = 1.0
    links.new(centred(split.outputs["Y"], half * 0.62), direction.inputs["Z"])
    turn = nodes.new("ShaderNodeVectorRotate")
    turn.rotation_type = "Z_AXIS"
    turn.inputs["Angle"].default_value = math.radians(yaw_deg)
    links.new(direction.outputs["Vector"], turn.inputs["Vector"])
    env = nodes.new("ShaderNodeTexEnvironment")
    env.image = bpy.data.images.load(str(ASSETS / "rooms" / (slug + ".hdr")), check_existing=True)
    links.new(turn.outputs["Vector"], env.inputs["Vector"])
    cap = nodes.new("ShaderNodeMix")
    cap.data_type = "RGBA"
    cap.blend_type = "DARKEN"
    cap.inputs["Factor"].default_value = 1.0
    cap.inputs["B"].default_value = (2.5, 2.5, 2.5, 1.0)
    links.new(env.outputs["Color"], cap.inputs["A"])
    colour = nodes.new("ShaderNodeMix")
    colour.data_type = "RGBA"
    colour.blend_type = "MULTIPLY"
    colour.inputs["Factor"].default_value = 1.0
    colour.inputs["B"].default_value = (*tint, 1.0)
    links.new(cap.outputs["Result"], colour.inputs["A"])
    emit = nodes.new("ShaderNodeEmission")
    emit.inputs["Strength"].default_value = strength
    links.new(colour.outputs["Result"], emit.inputs["Color"])
    links.new(emit.outputs["Emission"], out.inputs["Surface"])
    return mat


# Rooms by storey. Each lit window picks one and a view direction.
ROOMS_DOWN = ["lythwood_lounge", "reading_room", "entrance_hall", "kiara_interior", "wooden_lounge", "fireplace"]
ROOMS_UP = ["lythwood_room", "cabin", "hotel_room"]
_interiors = {}


def room_view(library, slug, yaw_deg, level):
    """Material name for a room backdrop, made on first use. level: bright, dim or tv."""
    yaw = int(round(yaw_deg / 15.0) * 15) % 360
    name = f"interior_{slug}_{yaw}_{level}"
    if name not in library:
        strength, tint = {"bright": (4.2, (1.0, 0.86, 0.68)), "dim": (2.0, (1.0, 0.78, 0.56)),
                          "tv": (2.2, (0.6, 0.74, 1.0))}[level]
        library[name] = interior(name, slug, yaw, strength, tint)
    return name


def water(name):
    mat, nodes, links, bsdf = _new(name)
    _set(bsdf, color=(0.55, 0.82, 0.86), rough=0.02, transmission=1.0, ior=1.333)
    noise = nodes.new("ShaderNodeTexNoise")
    noise.inputs["Scale"].default_value = 3.2
    noise.inputs["Detail"].default_value = 3.0
    bump = nodes.new("ShaderNodeBump")
    bump.inputs["Strength"].default_value = 0.12
    bump.inputs["Distance"].default_value = 0.03
    links.new(noise.outputs["Fac"], bump.inputs["Height"])
    links.new(bump.outputs["Normal"], bsdf.inputs["Normal"])
    return mat


WARM = (1.0, 0.72, 0.42)
WARM_WHITE = (1.0, 0.83, 0.62)
COOL = (0.72, 0.84, 1.0)


def library():
    """Every named material the builder uses."""
    m = {}
    m["siding"] = paint("siding", (0.86, 0.855, 0.82), 0.52, bump=0.35, bump_scale=140)
    m["trim"] = paint("trim", (0.9, 0.895, 0.87), 0.38, bump=0.15, bump_scale=200)
    m["sash"] = paint("sash", (0.9, 0.895, 0.87), 0.3)
    m["shutter"] = paint("shutter", (0.012, 0.018, 0.016), 0.42, bump=0.2, bump_scale=180)
    m["door"] = paint("door", (0.014, 0.03, 0.026), 0.2, coat=0.6)
    m["garage_door"] = paint("garage_door", (0.87, 0.865, 0.84), 0.4, bump=0.12, bump_scale=200)
    m["glass"] = glass("glass")
    m["lantern_glass"] = glass("lantern_glass", (0.98, 0.95, 0.88), 0.06)
    m["roof"] = pbr("roof", "roof_slates_03", 2.2, value=0.62, bump=1.4)
    m["ridge"] = paint("ridge", (0.07, 0.075, 0.08), 0.6)
    m["metal_roof"] = paint("metal_roof", (0.05, 0.055, 0.058), 0.35, metal=0.9)
    m["brick"] = pbr("brick", "large_red_bricks", 1.6, value=0.8, bump=1.2)
    m["stone"] = pbr("stone", "stone_wall", 2.0, value=0.85, bump=1.5)
    m["stone_cap"] = paint("stone_cap", (0.19, 0.2, 0.21), 0.7, bump=0.5, bump_scale=30)
    m["clay"] = paint("clay", (0.42, 0.17, 0.09), 0.75, bump=0.4, bump_scale=50)
    m["iron"] = paint("iron", (0.012, 0.012, 0.013), 0.42, metal=0.85)
    m["brass"] = paint("brass", (0.83, 0.62, 0.28), 0.25, metal=1.0)
    m["gutter"] = paint("gutter", (0.88, 0.875, 0.85), 0.35, metal=0.2)
    m["copper"] = paint("copper", (0.72, 0.4, 0.26), 0.35, metal=1.0)
    m["lamp_warm"] = emitter("lamp_warm", WARM, 160.0)
    m["lamp_cool"] = emitter("lamp_cool", COOL, 1200.0)
    m["lawn"] = pbr("lawn", "leafy_grass", 3.2, tint=(0.62, 0.78, 0.5), value=0.75, bump=1.0)
    m["gravel"] = pbr("gravel", "gravel_floor_02", 1.5, value=0.6, bump=2.2, rough_add=0.3)
    m["steel"] = paint("steel", (0.5, 0.51, 0.53), 0.32, metal=1.0)
    m["cushion"] = paint("cushion", (0.78, 0.76, 0.7), 0.85, bump=0.3, bump_scale=300)
    m["asphalt"] = pbr("asphalt", "asphalt_02", 4.0, value=0.7)
    m["flagstone"] = pbr("flagstone", "stone_tiles_02", 2.6, value=0.85, bump=1.3)
    m["pavers"] = pbr("pavers", "concrete_pavers_02", 2.0, value=0.9)
    m["mulch"] = pbr("mulch", "wood_chips", 1.6, value=0.7)
    m["cobble"] = pbr("cobble", "floor_pattern_01", 1.8, value=0.8, bump=1.4)
    m["concrete"] = paint("concrete", (0.42, 0.42, 0.4), 0.8, bump=0.6, bump_scale=25)
    m["wood_fence"] = paint("wood_fence", (0.2, 0.15, 0.1), 0.75, bump=0.6, bump_scale=40)
    m["water"] = water("water")
    m["pool_tile"] = paint("pool_tile", (0.3, 0.62, 0.72), 0.3)
    m["room_wall"] = paint("room_wall", (0.78, 0.74, 0.66), 0.8)
    m["room_floor"] = paint("room_floor", (0.3, 0.19, 0.11), 0.5)
    m["room_dark"] = paint("room_dark", (0.03, 0.03, 0.035), 0.9)
    m["room_glow"] = emitter("room_glow", WARM_WHITE, 2.4)
    m["room_glow_dim"] = emitter("room_glow_dim", WARM, 1.0)
    m["room_glow_tv"] = emitter("room_glow_tv", (0.55, 0.7, 1.0), 6.0)
    m["curtain"] = fabric("curtain", (0.82, 0.78, 0.7), 0.55)
    m["blind"] = fabric("blind", (0.88, 0.86, 0.8), 0.35)
    m["rubber"] = paint("rubber", (0.02, 0.02, 0.02), 0.85)
    m["plastic_dark"] = paint("plastic_dark", (0.03, 0.035, 0.04), 0.5)
    m["plastic_white"] = paint("plastic_white", (0.8, 0.8, 0.8), 0.4)
    return m
