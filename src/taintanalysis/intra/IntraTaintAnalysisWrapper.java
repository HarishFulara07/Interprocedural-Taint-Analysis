package taintanalysis.intra;

import java.util.List;
import java.util.Map;

import soot.Body;
import soot.BodyTransformer;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;

public class IntraTaintAnalysisWrapper extends BodyTransformer {
	String testFile;
	SootClass sootClass;
	List<SootMethod> methodList;
	
	public IntraTaintAnalysisWrapper(String testFile) {
		this.testFile = testFile;
		
		// Loading the input file
		sootClass = Scene.v().loadClassAndSupport(testFile);
		sootClass.setApplicationClass();
		Scene.v().loadNecessaryClasses();
		Scene.v().loadDynamicClasses();
		
		// Get all the methods in the input file
		methodList = sootClass.getMethods();
	}
	
	@Override
	@SuppressWarnings("rawtypes")
	protected void internalTransform(Body body, String phase, Map options) {
		SootMethod sootMethod = body.getMethod();
		//System.out.println(body);
		
		if(sootMethod.getName().equals("main")) {
			UnitGraph g = new BriefUnitGraph(sootMethod.getActiveBody());
			//System.out.println(body);
			new IntraTaintAnalysisMain(g, methodList);
		}
	}
}