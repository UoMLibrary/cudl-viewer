package ulcambridge.foundations.viewer;

import java.awt.Dimension;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.swing.ImageIcon;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import ulcambridge.foundations.viewer.model.Item;
import ulcambridge.foundations.viewer.model.Person;
import ulcambridge.foundations.viewer.model.Properties;

public class ItemFactory {

	// Stores a hashtable of all the items in a collection indexed by
	// CollectionId
	private static Hashtable<String, Hashtable<String, Item>> itemsInCollection = new Hashtable<String, Hashtable<String, Item>>();

	// Forces the application to load the collection information on startup.
	public static boolean initalised = initAllItems();

	/**
	 * Initalise the collections hashtable from information in the collections
	 * properties file.
	 */
	private synchronized static boolean initAllItems() {
		String[] collections = Properties.getString("collections").trim()
				.split(",");
		for (int i = 0; i < collections.length; i++) {
			initItems(collections[i]);
		}
		return true;
	}

	/**
	 * Initalise the collections hashtable from information in the collections
	 * properties file.
	 */
	private synchronized static void initItems(String collectionId) {

		Hashtable<String, Item> items = new Hashtable<String, Item>();

		String[] itemIds = Properties.getString(collectionId + ".items").trim()
				.split("\\s*,\\s*");
		for (int i = 0; i < itemIds.length; i++) {

			String itemId = itemIds[i];
			String itemTitle = "";
			List<Person> itemPeople = new ArrayList<Person>();
			String itemShelfLocator = "";
			String itemAbstract = "";
			String itemThumbnailURL = "";
			String thumbnailOrientation = "";

			if (itemId != null && !itemId.equals("")) {
				try {
					JSONObject json = JSONReader.readJsonFromUrl(Properties
							.getString("jsonURL") + itemId + ".json");

					JSONObject descriptiveMetadata = json.getJSONArray(
							"descriptiveMetadata").getJSONObject(0);

					itemTitle = descriptiveMetadata.getString("title");
					itemPeople = getPeopleFromJSON(descriptiveMetadata
							.getJSONArray("names"));
					itemShelfLocator = descriptiveMetadata
							.getString("shelfLocator");
					itemAbstract = descriptiveMetadata.getString("abstract");

					// Thumbnails
					itemThumbnailURL = descriptiveMetadata
							.getString("thumbnailUrl");
					if (Properties.getString("useProxy").equals("true")) {
						itemThumbnailURL = Properties.getString("proxyURL")
								+ descriptiveMetadata.getString("thumbnailUrl");
					}

					thumbnailOrientation = descriptiveMetadata
							.getString("thumbnailOrientation");

				} catch (IOException e) {
					e.printStackTrace();
				} catch (JSONException e) {
					e.printStackTrace();
				}

				Item item = new Item(itemId, itemTitle, itemPeople,
						itemShelfLocator, itemAbstract, itemThumbnailURL,
						thumbnailOrientation);

				items.put(itemId, item);

			}
		}

		itemsInCollection.put(collectionId, items);

	}

	public static Item getItemFromId(String id, String collectionId) {
		Hashtable<String, Item> items = itemsInCollection.get(collectionId);
		return items.get(id);
	}

	/**
	 * Returns the first matching item for that id in any collection.
	 * 
	 * @param id
	 * @return
	 */
	public static Item getItemFromId(String id) {

		Enumeration<String> collections = itemsInCollection.keys();
		while (collections.hasMoreElements()) {
			Hashtable<String, Item> items = itemsInCollection.get(collections
					.nextElement());
			Item item = items.get(id);
			if (item != null) {
				return item;
			}
		}
		return null;
	}

	public static List<Item> getItems(String collectionId) {
		Hashtable<String, Item> items = itemsInCollection.get(collectionId);
		ArrayList<Item> list = new ArrayList<Item>(items.values());
		Collections.sort(list);

		return list;
	}

	private static List<Person> getPeopleFromJSON(JSONArray names) {

		ArrayList<Person> people = new ArrayList<Person>();
		try {
			for (int i = 0; i < names.length(); i++) {
				JSONObject personJSON = names.getJSONObject(i);
				String fullForm = personJSON.getString("fullForm");
				String displayForm = personJSON.getString("displayForm");
				String authority = personJSON.getString("authority");
				String authorityURI = personJSON.getString("authorityURI");
				String valueURI = personJSON.getString("valueURI");
				String type = personJSON.getString("type");
				String role = personJSON.getString("role");
				Person person = new Person(fullForm, displayForm, authority,
						authorityURI, valueURI, type, role);
				people.add(person);
			}

		} catch (JSONException e) {
			e.printStackTrace();
		}
		
		return people;
	}

	private static Dimension getWidthHeightImage(URL url) {

		ImageIcon icon = new ImageIcon(url);
		return new Dimension(icon.getIconWidth(), icon.getIconHeight());

	}

}
