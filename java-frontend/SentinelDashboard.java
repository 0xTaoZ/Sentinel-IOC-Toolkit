import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Sentinel-IOC GUI Dashboard
 * Purpose: Display security scan results in a professional table.
 */
public class SentinelGUI {

    public static void main(String[] args) {
        // 1. Create the main Window (Frame)
        JFrame frame = new JFrame("Sentinel-IOC Command Center");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        // 2. Create Title Label
        JLabel title = new JLabel("Security Scan Analysis Report", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 20));
        title.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 3. Define Table Columns
        String[] columns = {"IOC Type", "Value", "Risk Level"};

        // 4. Sample Data (Next step: Load from result.json)
        String[][] data = {
            {"IPv4", "192.168.1.105", "Pending"},
            {"URL", "http://evil-site.net/malware.exe", "High Risk"},
            {"MD5", "44d88612fea8a8f36de82e1278abbb03", "Detected"}
        };

        // 5. Create the Table
        JTable table = new JTable(data, columns);
        JScrollPane scrollPane = new JScrollPane(table);

        // 6. Layout: Add everything to the frame
        frame.setLayout(new BorderLayout());
        frame.add(title, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);

        // 7. Make the window visible
        frame.setVisible(true);
    }
}
