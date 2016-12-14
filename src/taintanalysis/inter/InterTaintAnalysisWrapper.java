package taintanalysis.inter;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import soot.BodyTransformer;
import soot.Scene;
import soot.Body;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.annotation.purity.DirectedCallGraph;
import soot.jimple.toolkits.annotation.purity.SootMethodFilter;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.CallGraphBuilder;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.PseudoTopologicalOrderer;
import soot.toolkits.graph.UnitGraph;

public class InterTaintAnalysisWrapper extends BodyTransformer {
	String testFile;
	SootClass sootClass;
	List<SootMethod> methodList;
	HashMap<String, HashMap<Integer, Boolean>> summary;
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public InterTaintAnalysisWrapper(String testFile) {
		this.testFile = testFile;
		summary = new HashMap();
		
		// Loading the input file
		sootClass = Scene.v().loadClassAndSupport(testFile);
		sootClass.setApplicationClass();
		Scene.v().loadNecessaryClasses();
		Scene.v().loadDynamicClasses();
		
		// Creating the call graph
		CallGraphBuilder cgb = new CallGraphBuilder();
		cgb.build();
		CallGraph cg = cgb.getCallGraph();

		methodList = sootClass.getMethods();
		
		Iterator<SootMethod> itr = methodList.iterator();
		
		SootMethodFilter smf = new SootMethodFilter() {
			@Override
			public boolean want(SootMethod method) {
				// analyze only those methods which are defined in the input class
				return methodList.contains(method) && !method.getName().equals("<init>")
						&& !method.getName().equals("main");
			}
		};
		
		// Creating directed call graph from call graph
		DirectedCallGraph graph = new DirectedCallGraph(cg, smf, itr, false);  		
		
		/*Iterator it = graph.iterator();
		System.out.println("Printing directed call graph\n");
		while(it.hasNext()) {
			System.out.println(it.next());
		}*/
		
		// Creating a reverse topological ordered graph for directed call graph
		PseudoTopologicalOrderer pto = new PseudoTopologicalOrderer();
		List<SootMethod> order = pto.newList(graph, true);
		
		/*it=order.iterator();
		System.out.println("\nPrinting reverse topological order call graph\n");
		while(it.hasNext()){          
			System.out.println(((SootMethod)it.next()).getName());
		}
		System.out.println();*/
		
		buildSummary(order);
	}
	
	private void buildSummary(List<SootMethod> order) {
		// Calculating summary for class methods
		for(SootMethod sootMethod : order) {
			UnitGraph g = new BriefUnitGraph(sootMethod.getActiveBody());			
			
			// Number of parameters in the method
			int paramsCount = sootMethod.getParameterCount();
			
			summary.put(sootMethod.getName(), new HashMap<Integer, Boolean>());
			
			for(int i = 0; i < paramsCount; ++i) {
				// Initially all method parameters lead to taintness
				// What we mean is that, if parameter i is tainted then method returns a tainted value
				summary.get(sootMethod.getName()).put(i, true);
			}
			
			for(int i = 0; i < paramsCount; ++i) {
				// Analyze method by making ith parameter tainted
				IntraTaintAnalysisMain object = new IntraTaintAnalysisMain(g, summary, i);
				
				// if method returns an untainted value
				if(!object.getTaintReturn()) {
					summary.get(sootMethod.getName()).put(i, false);
				}
			}
		}
		
		// printing the summary
		System.out.println("Summary\n");
		@SuppressWarnings("rawtypes")
		Iterator it1 = summary.entrySet().iterator();
		
		while(it1.hasNext()) {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			Map.Entry<String, HashMap<Integer, Boolean>> pair1 = (Map.Entry) it1.next();
			
			System.out.println("Method: " + pair1.getKey());
			
			@SuppressWarnings("rawtypes")
			Iterator it2 = pair1.getValue().entrySet().iterator();
			
			while(it2.hasNext()) {
				@SuppressWarnings("unchecked")
				Map.Entry<Integer, Boolean> pair2= (Entry<Integer, Boolean>) it2.next();
				
				System.out.println(pair2.getKey() + " : " + pair2.getValue());
			}
		}
	}

	@Override
	@SuppressWarnings("rawtypes")
	protected void internalTransform(Body body, String phase, Map options) {
		SootMethod sootMethod = body.getMethod();
		
		if(sootMethod.getName().equals("main")) {
			//System.out.println(body);
			UnitGraph g = new BriefUnitGraph(sootMethod.getActiveBody());
			new InterTaintAnalysisMain(g, methodList, summary);
		}
	}
}