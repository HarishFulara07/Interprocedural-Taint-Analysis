package taintanalysis.intra;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.tagkit.AbstractHost;
import soot.tagkit.LineNumberTag;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;

@SuppressWarnings("rawtypes")
public class IntraTaintAnalysisMain extends ForwardFlowAnalysis {
	Body body;
	FlowSet inval, outval;
	ArrayList<String> origVars = new ArrayList<String>();
	List<SootMethod> methodList;
	
	// For output purposes
	Map<Integer, HashSet<String>> funcReportTaint = new HashMap<Integer, HashSet<String>>();
	Map<Integer, HashSet<String>> funcReportUntaint = new HashMap<Integer, HashSet<String>>();
	HashSet<Integer> sinkReportTaint = new HashSet<Integer>();
	HashSet<Integer> sinkReportUntaint = new HashSet<Integer>();
	
	@SuppressWarnings("unchecked")
	public IntraTaintAnalysisMain(UnitGraph g, List<SootMethod> methodList) {
		super(g);
		body = g.getBody();
		this.methodList = methodList;
		
		// carry out actual flow analysis
		doAnalysis();
		
		// Outputting the result in the specified format
		System.out.println();
		// Print function taintness report
		printFunctionReport();
		System.out.println();
		// Print sink report
		printSinkReport();
		System.out.println();
	}
	
	@Override
	// defining gen and kill set for a statment
	protected void flowThrough(Object in, Object unit, Object out) {
		inval = (FlowSet)in;
		outval = (FlowSet)out;
		Stmt stmt = (Stmt)unit;
		
		inval.copy(outval);
		
		// Kill and Gen operations
		
		// check if the statement is an assignment statment
		if(stmt instanceof AssignStmt) {
			String[] str = stmt.toString().split("[\\s\\<\\.]+");
			
			// if the assignment statement correspond to a print statement
			if(str.length > 7 && str[3].equalsIgnoreCase("lang") &&
					str[7].equalsIgnoreCase("printstream")) {
				outval.remove(((AssignStmt) stmt).getLeftOp().toString());
			}
			// if the assignment statement correspond to an invoke statement
			else if(str.length > 5 && (str[2].equalsIgnoreCase("virtualinvoke") ||
					str[2].equalsIgnoreCase("staticinvoke") || str[2].equalsIgnoreCase("specialinvoke"))) {
				List<Value> args = stmt.getInvokeExpr().getArgs();
				SootMethod sootMethod = stmt.getInvokeExpr().getMethod();
				
				boolean tainted = false;
				
				for(Value arg : args) {
					if(inval.contains(arg.toString())) {
						tainted = true;
						break;
					}
				}
				
				LineNumberTag tag = (LineNumberTag) ((AbstractHost) unit).getTag("LineNumberTag");
				int lineNumber = 0;
				
				if(tag != null) {
					lineNumber = tag.getLineNumber();
				}
				
				if(tainted) {
					if(methodList.contains(sootMethod)) {
						
						if(!funcReportTaint.containsKey(lineNumber)) {
							funcReportTaint.put(lineNumber, new HashSet<String>());
						}
							
						funcReportTaint.get(lineNumber).add(sootMethod.getName());
						
					}
					outval.add(((AssignStmt) stmt).getLeftOp().toString());
				}
				else {
					if(methodList.contains(sootMethod)) {
						
						if(!funcReportUntaint.containsKey(lineNumber)) {
							funcReportUntaint.put(lineNumber, new HashSet<String>());
						}
						
						funcReportUntaint.get(lineNumber).add(sootMethod.getName());
						
					}
					outval.remove(((AssignStmt) stmt).getLeftOp().toString());
				}
			}
			else {
				String[] vars = ((AssignStmt) stmt).getRightOp().toString().split("[\\+\\-\\*\\/\\%\\[\\]]+");
				
				boolean tainted = false;
				
				for(int i = 0; i < vars.length; ++i) {
					vars[i] = vars[i].trim();
					
					if(inval.contains(vars[i])) {
						tainted = true;
						break;
					}
				}
				
				// if the operand on the LHS of assignment statement is not tainted, kill it
				if(!tainted) {
					outval.remove(((AssignStmt) stmt).getLeftOp().toString());
				}
				// else, generate it
				else {
					outval.add(((AssignStmt) stmt).getLeftOp().toString());
				}
			}
		}
		
		if(stmt instanceof InvokeStmt) {
			String invokeStmtName = stmt.getInvokeExpr().getMethod().getName();
			
			if(invokeStmtName.length() >= 5 && invokeStmtName.substring(0, 5).equalsIgnoreCase("print")) {
				String printedVar = stmt.getInvokeExpr().getArg(0).toString();
				
				LineNumberTag tag = (LineNumberTag) ((AbstractHost) unit).getTag("LineNumberTag");
				int lineNumber = 0;
				
				if(tag != null) {
					lineNumber = tag.getLineNumber();
				}
				
				if(outval.contains(printedVar)) {				
					sinkReportTaint.add(lineNumber);
				}
				else {
					sinkReportUntaint.add(lineNumber);
				}
			}
		}
	}
	
	@Override
	protected void copy(Object source, Object dest) {
		FlowSet srcSet = (FlowSet)source;
		FlowSet	destSet = (FlowSet)dest;
		srcSet.copy(destSet);
		
	}
	
	@Override
	protected void merge(Object in1, Object in2, Object out) {
		FlowSet inval1=(FlowSet)in1;
		FlowSet inval2=(FlowSet)in2;
		FlowSet outSet=(FlowSet)out;
		// Taint analysis is a MAY analysis
		inval1.union(inval2, outSet);
	}
	
	
	@Override
	// Contents of the lattice element for the entry point
	protected Object entryInitialFlow() {
		ArraySparseSet arraySparseSet = new ArraySparseSet();
		
		// get method parameters
		ArrayList<String> params = getMethodParamsAndLocals(body.getMethod().getParameterCount());
		
		for(String param : params) {
			// all method parameters are tainted
			// so, add them to the content of the lattice element for the entry point
			arraySparseSet.add(param);
		}
		
		//System.out.println(params);
		return arraySparseSet;
	}
	
	@Override
	// Contents of the lattice element for all the other points
	protected Object newInitialFlow() {
		return new ArraySparseSet();
	}
	
	// function to get parameters of a method
	private ArrayList<String> getMethodParamsAndLocals(int paramsCount) {
		ArrayList<String> params = new ArrayList<String>();
		ArrayList<String> locals = new ArrayList<String>();
		
		// loop through all local variables inside the soot representation of the java method
		// method parameters are also represented as local variables in soot representation of the java method
		for(Local local: body.getLocals()) {
			
			if(local.getName().equals("this")) {
				locals.add(local.getName());
			}
			else if(paramsCount == 0) {
				locals.add(local.getName());
				
				if(!local.getName().substring(0, 1).equals("$")) {
					origVars.add(local.getName());
				}
			}
			else {
				params.add(local.getName());
				origVars.add(local.getName());
				--paramsCount;
			}
		}
		
		return params;
	}
	
	void printFunctionReport() {
		
		Map<Integer, HashSet<String>> funcReportTaintSorted = 
				new TreeMap<Integer, HashSet<String>>(funcReportTaint);
		Map<Integer, HashSet<String>> funcReportUntaintSorted = 
				new TreeMap<Integer, HashSet<String>>(funcReportUntaint);
		
		Iterator it = funcReportTaintSorted.entrySet().iterator();
		
		while(it.hasNext()) {
			@SuppressWarnings("unchecked")
			Map.Entry<Integer, HashSet<String>> pair = (Map.Entry) it.next();
			
			for(String methodName : pair.getValue()) {
				System.out.println("Summary of " + methodName + " at " + pair.getKey() +
						" : Returns a tainted value");
			}
		}
		
		System.out.println();
		
		it = funcReportUntaintSorted.entrySet().iterator();
		
		while(it.hasNext()) {
			@SuppressWarnings("unchecked")
			Map.Entry<Integer, HashSet<String>> pair = (Map.Entry) it.next();
			
			for(String methodName : pair.getValue()) {
				if(funcReportTaint.containsKey(pair.getKey()) && 
						funcReportTaint.get(pair.getKey()).contains(methodName)) {
					continue;
				}
				System.out.println("Summary of " + methodName + " at " + pair.getKey() +
						" : Returns an untainted value");
			}
		}
	}
	
	void printSinkReport() {
		
		TreeSet<Integer> sinkReportTaintSorted = 
				new TreeSet<Integer>(sinkReportTaint);
		
		TreeSet<Integer> sinkReportUntaintSorted = 
				new TreeSet<Integer>(sinkReportUntaint);
		
		for(Integer lineNum : sinkReportTaintSorted) {
			System.out.println("Sink at " + lineNum + ", tainted value printed");
		}
		
		System.out.println();
		
		for(Integer lineNum : sinkReportUntaintSorted) {
			if(!sinkReportTaint.contains(lineNum)) {
				System.out.println("Sink at " + lineNum + ", untainted value printed");
			}
		}
	}
}