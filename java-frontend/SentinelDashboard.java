import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Sentinel-IOC Advanced Dashboard
 * Purpose: Load data from Python and highlight high-risk items.
 */
public class SentinelDashboard {

    public static void main(String[] args) {
        // 1. Create the Window
        JFrame frame = new JFrame("Sentinel-IOC v0.1");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 450);

        // 2. Table Column Headers
        String[] columns = {"Value", "Type", "Risk Score", "Country", "Action"};
        DefaultTableModel model = new DefaultTableModel(columns, 0);
        JTable table = new JTable(model);

        // 3. Logic to read the Python result file
        try {
            // Path to our JSON result
            String path = "../python-backend/result.json";
            System.out.println("[*] Loading data from: " + path);
            
            // For now, let's simulate the data loading from the file
            // (In real development, we would use an 'org.json' library here)
            // Based on our last Python run, we manually add these as a test:
            model.addRow(new Object[]{"185.156.177.10", "IPv4", "100", "NL", "BLOCK"});
            model.addRow(new Object[]{"8.8.8.8", "IPv4", "0", "US", "ALLOW"});
            model.addRow(new Object[]{"http://evil-site.net", "URL", "85", "Unknown", "SCAN"});

        } catch (Exception e) {
            System.out.println("[!] Error loading result.json");
        }

        // 4. Professional Touch: Highlight CRITICAL rows in RED
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean isS, boolean hasF, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, isS, hasF, row, col);
                
                // If Risk Score is 100, make the text RED
                if (value.equals("100")) {
                    c.setForeground(Color.RED);
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else {
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        });

        // 5. Layout Setup
        frame.setLayout(new BorderLayout());
        JLabel header = new JLabel("Sentinel-IOC Live Analysis Report", SwingConstants.CENTER);
        header.setFont(new Font("Arial", Font.BOLD, 18));
        header.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

        frame.add(header, BorderLayout.NORTH);
        frame.add(new JScrollPane(table), BorderLayout.CENTER);

        // 6. Display the Window
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }
}
