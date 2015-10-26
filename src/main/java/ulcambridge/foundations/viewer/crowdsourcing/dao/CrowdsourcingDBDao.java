package ulcambridge.foundations.viewer.crowdsourcing.dao;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.sql.DataSource;

import org.postgresql.util.PGobject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.RowMapper;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ulcambridge.foundations.viewer.crowdsourcing.model.Annotation;
import ulcambridge.foundations.viewer.crowdsourcing.model.DocumentAnnotations;
import ulcambridge.foundations.viewer.crowdsourcing.model.DocumentTags;
import ulcambridge.foundations.viewer.crowdsourcing.model.JSONConverter;
import ulcambridge.foundations.viewer.crowdsourcing.model.Tag;
import ulcambridge.foundations.viewer.crowdsourcing.model.UserAnnotations;
import ulcambridge.foundations.viewer.utils.Utils;

/**
 * 
 * @author Lei
 *
 */
public class CrowdsourcingDBDao implements CrowdsourcingDao {

	private JdbcTemplate jdbcTemplate;

	@Autowired
	public void setDataSource(DataSource dataSource) {
		this.jdbcTemplate = new JdbcTemplate(dataSource);
	}

	@Override
	public DocumentAnnotations getAnnotations(String userId, String documentId, int documentPageNo) {
		// query
		JsonObject uda = sqlGetAnnotations(userId, documentId, documentPageNo);

		if (!uda.has("oid")) {
			uda.addProperty("oid", userId);
			uda.addProperty("docId", documentId);
			uda.addProperty("total", 0);
			uda.add("annotations", new JsonArray());
		}

		return new JSONConverter().toDocumentAnnotations(uda);
	}

	@Override
	public DocumentTags getTagsByDocument(String documentId) {
		// query
		JsonObject dt = sqlGetTags(documentId);

		if (!dt.has("docId")) {
			dt.addProperty("docId", documentId);
			dt.addProperty("total", 0);
			dt.add("tags", new JsonArray());
		}

		return new JSONConverter().toDocumentTags(dt);
	}

	@Override
	public DocumentTags getRemovedTags(String userId, String documentId) {
		// query
		JsonObject json = sqlGetRemovedTags(userId, documentId);

		if (!json.has("docId")) {
			json.addProperty("oid", userId);
			json.addProperty("docId", documentId);
			json.addProperty("total", 0);
			json.add("tags", new JsonArray());
		}

		return new JSONConverter().toDocumentTags(json);
	}

	@Override
	public int addAnnotation(String userId, String documentId, Annotation annotation) throws SQLException {
		DocumentAnnotations da = getAnnotations(userId, documentId, 0);
		List<Annotation> annotations = da.getAnnotations();

		if (annotations.contains(annotation)) {
			annotations.remove(annotation);
		}
		annotation.setDate(Utils.getCurrentDateTime());
		annotation.setUuid(UUID.randomUUID());
		annotations.add(annotation);
		da.setTotal(annotations.size());

		JsonObject newJson = new JSONConverter().toJsonDocumentAnnotations(da);

		// query
		int rowsAffected = sqlUpsertAnnotations(userId, documentId, newJson);

		return 1;
	}

	@Override
	public int removeAnnotation(String userId, String documentId, UUID AnnotationUuid) throws SQLException {
		DocumentAnnotations da = getAnnotations(userId, documentId, 0);
		List<Annotation> annotations = da.getAnnotations();

		if (annotations.size() < 0)
			return 0;

		for (Annotation annotation : annotations) {
			if (annotation.getUuid().toString().equals(AnnotationUuid.toString())) {
				annotations.remove(annotation);
				break;
			}
		}
		da.setTotal(annotations.size());

		JsonObject newJson = new JSONConverter().toJsonDocumentAnnotations(da);

		// query 
		int rowsAffected = sqlUpdateAnnotations(userId, documentId, newJson);

		return 1;
	}

	@Override
	public int addTag(String documentId, DocumentTags documentTags) throws SQLException {
		JsonObject newJson = new JSONConverter().toJsonDocumentTags(documentTags);

		// query
		int rowsAffected = sqlUpsertTag(documentId, newJson);

		return 1;
	}

	@Override
	public int addRemovedTag(String userId, String documentId, Tag removedTag) throws SQLException {
		DocumentTags dt = getRemovedTags(userId, documentId);
		List<Tag> removedTags = dt.getTags();

		if (removedTags.contains(removedTag)) {
			removedTags.remove(removedTag);
		} else {
			removedTags.add(removedTag);
		}
		dt.setTotal(removedTags.size());

		JsonObject newJson = new JSONConverter().toJsonDocumentTags(dt);

		// query
		int rowsAffected = sqlUpsertRemovedTags(userId, documentId, newJson);

		return 1;
	}

	@Override
	public DocumentAnnotations getAnnotationsByDocument(String documentId) {
		// query
		List<JsonObject> docAnnotationList = sqlGetAnnotationsByDocument(documentId);

		JSONConverter jc = new JSONConverter();

		Set<Annotation> annotations = new HashSet<Annotation>();
		for (JsonObject docAnnos : docAnnotationList) {
			if (!docAnnos.has("annotations"))
				continue;
			JsonArray annos = docAnnos.getAsJsonArray("annotations");
			Iterator<JsonElement> it = annos.iterator();
			while (it.hasNext()) {
				JsonObject anno = (JsonObject) it.next();
				Annotation annotation = jc.toAnnotation(anno);
				annotations.add(annotation);
			}
		}

		JsonObject json = new JsonObject();
		JsonArray distinctAnnos = new JsonArray();

		for (Annotation annotation : annotations) {
			distinctAnnos.add(jc.toJsonAnnotation(annotation));
		}

		json.addProperty("docId", documentId);
		json.addProperty("total", distinctAnnos.size());
		json.add("annotations", distinctAnnos);

		return jc.toDocumentAnnotations(json);
	}

	@Override
	public DocumentTags getRemovedTagsByDocument(String documentId) {
		// query
		List<JsonObject> docRemovedTagList = sqlGetRemovedTagsByDocument(documentId);

		JSONConverter jc = new JSONConverter();

		Set<Tag> removedTags = new HashSet<Tag>();
		for (JsonObject docRemovedTags : docRemovedTagList) {
			if (!docRemovedTags.has("tags"))
				continue;
			JsonArray rmvTags = docRemovedTags.getAsJsonArray("tags");
			Iterator<JsonElement> it = rmvTags.iterator();
			while (it.hasNext()) {
				JsonObject rmvTag = (JsonObject) it.next();
				Tag tag = jc.toTag(rmvTag);
				removedTags.add(tag);
			}
		}

		JsonObject json = new JsonObject();
		JsonArray distinctRemovedTags = new JsonArray();

		for (Tag tag : removedTags) {
			distinctRemovedTags.add(jc.toJsonTag(tag));
		}

		json.addProperty("docId", documentId);
		json.addProperty("total", distinctRemovedTags.size());
		json.add("tags", distinctRemovedTags);

		return jc.toDocumentTags(json);
	}

	@Override
	public UserAnnotations getAnnotationsByUser(String userId) {
		// query
		List<JsonObject> userAnnotationList = sqlGetAnnotationsByUser(userId);

		JsonObject json = new JsonObject();
		JsonArray userAnnotationJArray = new JsonArray();
		int total = 0;

		for (JsonObject userAnnotations : userAnnotationList) {
			if (userAnnotations.has("oid")) {
				userAnnotations.remove("oid");
				if (userAnnotations.has("annotations")) {
					total += userAnnotations.getAsJsonArray("annotations").size();
				}
				userAnnotationJArray.add(userAnnotations);
			}
		}

		json.addProperty("oid", userId);
		json.addProperty("total", total);
		json.add("annotations", userAnnotationJArray);

		return new JSONConverter().toUserAnnotations(json);
	}

	@Override
	public List<String> getAnnotatedDocuments() {
		String query = "SELECT DISTINCT \"docId\" FROM \"DocumentAnnotations\"";

		return jdbcTemplate.query(query, new RowMapper<String>() {
			@Override
			public String mapRow(ResultSet rs, int rowNum) throws SQLException {
				String docId = rs.getString("docId");
				return docId;
			}
		});
	}

	@Override
	public List<String> getTaggedDocuments() {
		String query = "SELECT DISTINCT \"docId\" FROM \"DocumentTags\"";

		return jdbcTemplate.query(query, new RowMapper<String>() {
			@Override
			public String mapRow(ResultSet rs, int rowNum) throws SQLException {
				String docId = rs.getString("docId");
				return docId;
			}
		});
	}

	private JsonObject sqlGetAnnotations(final String userId, final String documentId, final int documentPageNo) {
		String query = "SELECT annos FROM \"DocumentAnnotations\" WHERE \"oid\" = ? AND \"docId\" = ?";

		return jdbcTemplate.query(query, new Object[] { userId, documentId }, new ResultSetExtractor<JsonObject>() {
			@Override
			public JsonObject extractData(ResultSet rs) throws SQLException {
				List<String> udas = new ArrayList<String>();
				while (rs.next()) {
					String anno = rs.getString("annos");
					udas.add(anno);
				}
				return (udas.isEmpty()) ? new JsonObject() : (JsonObject) new JsonParser().parse(udas.get(0));
			}
		});
	}

	private JsonObject sqlGetTags(final String documentId) {
		String query = "SELECT tags FROM \"DocumentTags\" WHERE \"docId\" = ?";

		return jdbcTemplate.query(query, new Object[] { documentId }, new ResultSetExtractor<JsonObject>() {
			@Override
			public JsonObject extractData(ResultSet rs) throws SQLException, DataAccessException {
				List<String> dts = new ArrayList<String>();
				while (rs.next()) {
					String json = rs.getString("tags");
					dts.add(json);
				}
				return (dts.isEmpty()) ? new JsonObject() : (JsonObject) new JsonParser().parse(dts.get(0));
			}
		});
	}

	private JsonObject sqlGetRemovedTags(final String userId, final String documentId) {
		String query = "SELECT removedtags FROM \"DocumentRemovedTags\" WHERE \"oid\" = ? AND \"docId\" = ?";

		return jdbcTemplate.query(query, new Object[] { userId, documentId }, new ResultSetExtractor<JsonObject>() {
			@Override
			public JsonObject extractData(ResultSet rs) throws SQLException, DataAccessException {
				List<String> removedTags = new ArrayList<String>();
				while (rs.next()) {
					String json = rs.getString("removedtags");
					removedTags.add(json);
				}
				return (removedTags.isEmpty()) ? new JsonObject() : (JsonObject) new JsonParser().parse(removedTags.get(0));
			}
		});
	}

	private int sqlUpsertAnnotations(String userId, String documentId, JsonObject newJson) throws SQLException {
		String query = "UPDATE \"DocumentAnnotations\" SET \"annos\" = ? WHERE \"oid\" = ? AND \"docId\" = ?; "
				+ "INSERT INTO \"DocumentAnnotations\" (\"oid\", \"docId\", \"annos\") " + "SELECT ?, ?, ? "
				+ "WHERE NOT EXISTS (SELECT * FROM \"DocumentAnnotations\" WHERE \"oid\" = ? AND \"docId\" = ?);";

		PGobject json = new PGobject();
		json.setType("json");
		json.setValue(newJson.toString());

		return jdbcTemplate.update(query, new Object[] { json, userId, documentId, userId, documentId, json, userId, documentId });
	}

	private int sqlUpdateAnnotations(String userId, String documentId, JsonObject newJson) throws SQLException {
		String query = "UPDATE \"DocumentAnnotations\" SET \"annos\" = ? WHERE \"oid\" = ? AND \"docId\" = ?;";

		PGobject json = new PGobject();
		json.setType("json");
		json.setValue(newJson.toString());

		return jdbcTemplate.update(query, new Object[] { json, userId, documentId });
	}

	private int sqlUpsertTag(String documentId, JsonObject newJson) throws SQLException {
		String query = "UPDATE \"DocumentTags\" SET \"tags\" = ? WHERE \"docId\" = ?; " + "INSERT INTO \"DocumentTags\" (\"docId\", \"tags\") "
				+ "SELECT ?, ? " + "WHERE NOT EXISTS (SELECT * FROM \"DocumentTags\" WHERE \"docId\" = ?);";

		PGobject json = new PGobject();
		json.setType("json");
		json.setValue(newJson.toString());

		return jdbcTemplate.update(query, new Object[] { json, documentId, documentId, json, documentId });
	}

	private int sqlUpsertRemovedTags(String userId, String documentId, JsonObject newJson) throws SQLException {
		String query = "UPDATE \"DocumentRemovedTags\" SET \"removedtags\" = ? WHERE \"oid\" = ? AND \"docId\" = ?; "
				+ "INSERT INTO \"DocumentRemovedTags\" (\"oid\", \"docId\", \"removedtags\") " + "SELECT ?, ?, ? "
				+ "WHERE NOT EXISTS (SELECT * FROM \"DocumentRemovedTags\" WHERE \"oid\" = ? AND \"docId\" = ?);";

		PGobject json = new PGobject();
		json.setType("json");
		json.setValue(newJson.toString());

		return jdbcTemplate.update(query, new Object[] { json, userId, documentId, userId, documentId, json, userId, documentId });
	}

	private List<JsonObject> sqlGetAnnotationsByDocument(final String documentId) {
		String query = "SELECT annos FROM \"DocumentAnnotations\" WHERE \"docId\" = ?";

		return jdbcTemplate.query(query, new Object[] { documentId }, new RowMapper<JsonObject>() {
			@Override
			public JsonObject mapRow(ResultSet rs, int rowNum) throws SQLException {
				String tag = rs.getString("annos");
				return (JsonObject) new JsonParser().parse(tag);
			}
		});
	}

	private List<JsonObject> sqlGetRemovedTagsByDocument(String documentId) {
		String query = "SELECT removedtags FROM \"DocumentRemovedTags\" WHERE \"docId\" = ?";

		return jdbcTemplate.query(query, new Object[] { documentId }, new RowMapper<JsonObject>() {
			@Override
			public JsonObject mapRow(ResultSet rs, int rowNum) throws SQLException {
				String removedTag = rs.getString("removedtags");
				return (JsonObject) new JsonParser().parse(removedTag);
			}
		});
	}

	private List<JsonObject> sqlGetAnnotationsByUser(final String userId) {
		String query = "SELECT annos FROM \"DocumentAnnotations\" WHERE \"oid\" = ?";

		return jdbcTemplate.query(query, new Object[] { userId }, new RowMapper<JsonObject>() {
			@Override
			public JsonObject mapRow(ResultSet rs, int rowNum) throws SQLException {
				String tag = rs.getString("annos");
				return (JsonObject) new JsonParser().parse(tag);
			}
		});
	}

}