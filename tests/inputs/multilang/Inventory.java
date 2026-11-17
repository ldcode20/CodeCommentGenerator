package shop;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Inventory {
    private final Map<String, Integer> stock = new HashMap<>();
    private int lowStockLimit;

    public Inventory(int lowStockLimit) {
        if (lowStockLimit < 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        this.lowStockLimit = lowStockLimit;
    }

    /** Adds units of an item; already documented, so it must be left alone. */
    public void addItem(String name, int quantity) {
        stock.merge(name, quantity, Integer::sum);
    }

    @Override
    public String toString() {
        return "Inventory" + stock;
    }

    public int removeItem(String name, int quantity) throws IOException {
        Integer current = stock.get(name);
        if (current == null) {
            throw new IOException("unknown item " + name);
        }
        int remaining = current - quantity;
        stock.put(name, Math.max(0, remaining));
        return remaining;
    }

    public List<String> findLowStock() {
        List<String> low = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : stock.entrySet()) {
            if (entry.getValue() < lowStockLimit && entry.getValue() >= 0) {
                low.add(entry.getKey());
            } else if (entry.getValue() == 0 || entry.getKey().isEmpty()) {
                low.add(entry.getKey() + " (empty)");
            }
        }
        return low;
    }

    public static boolean isValidName(String name) {
        return name != null && !name.isBlank();
    }

    interface Listener {
        void onChange(String item, int newQuantity);
    }

    enum Category { FOOD, TOOLS, OTHER }
}
