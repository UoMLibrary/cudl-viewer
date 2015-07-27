package ulcambridge.foundations.viewer;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;

import ulcambridge.foundations.viewer.dao.CollectionsDao;
import ulcambridge.foundations.viewer.model.Collection;

public class CollectionFactory {

    private static Hashtable<String, Collection> collections;// = new Hashtable<String, Collection>();
    private static ArrayList<Collection> rootCollections;//= new ArrayList<Collection>();
    private static boolean initialised = false;
    private CollectionsDao collectionsDao;
    private static int collectionsRowCount;
    private static int itemsRowCount;
    private static int itemsinCollectionRowCount;
    private Timestamp timestamp;

    private static HashSet<String> allItemIds = new HashSet<String>(); // list of items in any collection

    @Autowired
    public void setCollectionsDao(CollectionsDao dao) {
        collectionsDao = dao;
        if (!initialised) {
            init();
        }
    }

    public boolean getInitialised() {
        return initialised;
    }

    public void init() {
        collections = new Hashtable<String, Collection>();
        rootCollections = new ArrayList<Collection>();
        List<String> collectionIds = collectionsDao.getCollectionIds();
        for (int i = 0; i < collectionIds.size(); i++) {
            String collectionId = collectionIds.get(i);
            Collection collection = collectionsDao.getCollection(collectionId);
            collections.put(collectionId, collection);
            allItemIds.addAll(collection.getItemIds());
        }

        // Setup the list of root collections used on the homescreen. 
        Iterator<Collection> iter = collections.values().iterator();
        while (iter.hasNext()) {
            Collection c = iter.next();
            String parentId = c.getParentCollectionId();

            if (parentId == null || parentId.length() == 0) {
                rootCollections.add(c);
            }
        }
        Collections.sort(rootCollections);
        collectionsRowCount = collectionsDao.getCollectionsRowCount();
        itemsRowCount = collectionsDao.getItemsRowCount();
        itemsinCollectionRowCount = collectionsDao.getItemsInCollectionsRowCount();
        timestamp = collectionsDao.getTimestamp();
        initialised = true;
    }

    public Collection getCollectionFromId(String id) {

        return collections.get(id);

    }

    /**
     * Returns the first collection with the given title or null if no
     * collections exist with that title.
     *
     * @param title
     * @return
     */
    public Collection getCollectionFromTitle(String title) {

        Iterator<Collection> c = getCollections().iterator();

        while (c.hasNext()) {
            Collection collection = c.next();
            if (collection.getTitle().equals(title)) {
                return collection;
            }
        }

        return null;
    }

    public List<Collection> getCollections() {

        ArrayList<Collection> list = new ArrayList<Collection>(
                collections.values());
        Collections.sort(list);
        return list;

    }

    public List<Collection> getRootCollections() {

        return rootCollections;

    }

    public List<Collection> getSubCollections(Collection collection) {

        List<Collection> output = new ArrayList<Collection>();
        Iterator<Collection> iter = collections.values().iterator();
        while (iter.hasNext()) {
            Collection c = iter.next();
            String parentId = c.getParentCollectionId();

            if (parentId != null && parentId.equals(collection.getId())) {
                output.add(c);
            }
        }
        Collections.sort(output);
        return output;
    }

    public Set<String> getAllItemIds() {

        return allItemIds;
    }

    public int getCollectionsRowCount() {
        return collectionsRowCount;
    }

    public int getItemsRowCount() {
        return itemsRowCount;
    }

    public int getItemsInCollectionsRowCount() {
        return itemsinCollectionRowCount;
    }

    //get the timestamp before database copy
    public Timestamp getOldTimestamp() {
        return timestamp;
    }

    //timestamp after database copy
    public Timestamp getCurrentTimestamp() {
        return collectionsDao.getTimestamp();
    }
}
