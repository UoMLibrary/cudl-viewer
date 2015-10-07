package ulcambridge.foundations.frontend.webpack;

import ulcambridge.foundations.frontend.FrontEndBuild;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * This class provides support for loading webpack build metadata,
 * which allows mapping from chunk names to their hashed filenames.
 *
 * <p>Build metadata is generated by the assets-webpack-plugin, and follows this
 * structure:
 *
 * <pre>{@code
 * {
 *     "foo": {
 *         "css": "chunk-dbc94d851bd7857e8419-foo.css",
 *         "cssMap": "chunk-dbc94d851bd7857e8419-foo.css.map"
 *    },
 *     "bar": {
 *         "css": "bar-ef82f626faad58600941.css",
 *         "cssMap": "bar-ef82f626faad58600941.css.map",
 *         "js": "bar-ef82f626faad58600941.js",
 *         "jsMap": "bar-ef82f626faad58600941.js.map"
 *     }
 * }
 * }</pre>
 */

// TODO: implementations based on webpack build meta as well as webpack dev server.
public interface WebpackBuild extends Iterable<WebpackBuild.Chunk> {

    Map<String, Chunk> getChunksByName();

    /**
     * Get the chunk with the given name.
     * @param name The name of the chunk
     * @return The chunk
     * @throws IllegalArgumentException If no chunk with the name exists
     */
    Chunk getChunk(String name);

    /**
     * Get a possible loading order for a chunk and its dependencies.
     *
     * @param chunk The chunk to be loaded.
     * @return A list of chunks in the order they are to be loaded
     *         (first to last).
     */
    List<Chunk> getLinearisedDependencies(Chunk chunk);
    List<Chunk> getLinearisedDependencies(String chunkName);

    interface Chunk {
        WebpackBuild getBuild();

        /**
         * @return The name of the chunk
         */
        String getName();

        /**
         * Chunks always have a javascript resource, and may have an extracted
         * CSS resource.
         *
         * @return The URI for the chunk's resource types..
         */
        Map<FrontEndBuild.ResourceType, URI> getUris();

        /**
         * Get a list of chunks that must be loaded before this chunk,
         * e.g. shared common chunks.
         */
        List<Chunk> getDependencies();
    }


}
