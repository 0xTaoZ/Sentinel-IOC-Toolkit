import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

/**
 * Sentinel-IOC GUI Dashboard
 * This class builds the visual window to display security findings.
 */
public class SentinelDashboard {

    public static void main(String[] args) {
        // 1. Create the main window (Frame)
        JFrame frame = new JFrame("Sentinel-IOC v0.1 - Security Command Center");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 500);

        // 2. Create a Title Header
        JLabel header = new JLabel("IOC Analysis & Threat Intelligence Report", SwingConstants.CENTER);
        header.setFont(new Font("Arial", Font.BOLD, 18));
        header.setBorder(BorderFactory.createEmptyBorder(15, 10, 15, 10));

        // 3. Define Table Columns
        // These match the data we extracted in Python
        String[] columns = {"IOC Value", "Type", "Risk Level", "Country", "Suggested Action"};

        // 4. Placeholder Data 
        // (In the next step, we will make Java read directly from result.json)
        DefaultTableModel model = new DefaultTableModel(columns, 0);
        
        // Let's add some example rows to see how it looks
        model.addRow(new Object[]{"185.156.177.10", "IPv4", "CRITICAL", "NL", "BLOCK"});
        model.addRow(new Object[]{"2001:0db8:85a3...", "IPv6", "CLEAN", "Unknown", "NONE"});
        model.addRow(new Object[]{"http://evil-site.net", "URL", "SUSPICIOUS", "Unknown", "MONITOR"});

        // 5. Create the Table and Scroll Pane
        JTable table = new JTable(model);
        JScrollPane scrollPane = new JScrollPane(table);
        
        // Professional Touch: Change row height
        table.setRowHeight(25);

        // 6. Layout: Add components to the window
        frame.setLayout(new BorderLayout());
        frame.add(header, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);

        // 7. Status Bar (At the bottom)
        JLabel statusBar = new JLabel(" Status: Python Analysis Engine - OK | API Connection - OK");
        statusBar.setPreferredSize(new Dimension(frame.getWidth(), 25));
        frame.add(statusBar, BorderLayout.SOUTH);

        // 8. Launch!
        frame.setLocationRelativeTo(null); // Center on screen
        frame.setVisible(true);
    }
}
