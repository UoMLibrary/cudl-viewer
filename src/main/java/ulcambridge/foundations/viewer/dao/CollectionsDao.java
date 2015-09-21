package ulcambridge.foundations.viewer.dao;

import java.util.List;

import ulcambridge.foundations.viewer.model.Collection;


public interface CollectionsDao {
	
	public List<String> getCollectionIds();
	public Collection getCollection(String collectionId);
	
	//
	// XXX tagging switch
	//

	public boolean isItemTaggable(String itemId);
	public boolean isCollectionTaggable(String collectionId);
	public String getCollectionId(String itemId);
}