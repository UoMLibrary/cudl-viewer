package ulcambridge.foundations.viewer.model;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This class contains a subset of the data in the JSON file for an item, which
 * we want to display at collection page level.
 * 
 * @author jennie
 * 
 */
public class Item implements Comparable<Item> {

	private static int orderCount = 1;
	private int order;
	private String id;
	private String title;
	private List<Person> people;
	private List<Person> authors;		
	private String shelfLocator;
	private String abstractText;
	private String thumbnailURL;
	private String thumbnailOrientation;
	private String abstractShort;

	public Item(String itemId, String itemTitle, List<Person> itemPeople, String shelfLocator,
			String abstractText, String thumbnailURL,
			String thumbnailOrientation) {

		this.id = itemId;
		this.title = itemTitle;
		this.people = itemPeople;
		this.authors = getPeopleByRole(itemPeople, "aut");
		this.shelfLocator = shelfLocator;
		this.abstractText = abstractText;
		this.thumbnailURL = thumbnailURL;
		this.thumbnailOrientation = thumbnailOrientation;

		String abstractShort = abstractText;
		abstractShort = abstractShort.replaceAll("\\<.*?>", ""); // remove tags
		// cut of next word after 120 characters
		if (abstractShort.length() > 120) {
			abstractShort = abstractShort.substring(0, 120 + abstractShort
					.substring(120).indexOf(" "));
		}
		this.abstractShort = abstractShort;

		orderCount++;
		this.order = orderCount;

	}

	public int getOrder() {
		return order;
	}

	public String getId() {
		return id;
	}

	public String getTitle() {
		return title;
	}
	
	public List<Person> getPeople() {
		return people;
	}	
	
	public List<Person> getAuthors() {
		return authors;
	}	

	public String getAbstract() {
		return abstractText;
	}

	/*
	 * Returns a shortened version of the abstract for display on the collection
	 * page. Max 120 characters (ish) and no html tags.
	 */
	public String getAbstractShort() {
		return abstractShort;
	}

	public String getThumbnailURL() {
		return thumbnailURL;
	}

	public String getThumbnailOrientation() {
		return thumbnailOrientation;
	}

	public String getShelfLocator() {
		return shelfLocator;
	}

	@Override
	public int compareTo(Item o) {
		if (this.getOrder() > o.getOrder()) {
			return 1;
		} else if (this.getOrder() == o.getOrder()) {
			return 0;
		}
		return -1;
		// return getId().compareTo(o.getId());
	}
	
	/**
	 * This method takes in a list of people and iterates through them to 
	 * produce a List of just the authors (role=aut) from that list. 
	 * 
	 * @param people
	 * @return
	 */
	private List<Person> getPeopleByRole(List<Person> people, String role) {
		
		ArrayList<Person> peopleWithRole = new ArrayList<Person>();
		Iterator<Person> peopleIt = people.iterator();
		while (peopleIt.hasNext()) {
			Person person = peopleIt.next();		
			if (role.equals(person.getRole())) {
				peopleWithRole.add(person);
			}
		}
		return peopleWithRole;
		
	}

}
