package taintanalysis.intra;

// This is a test Java file to test our analysis

public class Sample
{
  int factorialOne(int x)
  {
    return 1;
  }
  
  int factorial(int y)
  {
    int fact = factorialOne(y);
    fact = fact*y; 
    for(int i=2; i<y; ++i)
      fact = fact*i;
    return fact;
  }
  
  int numPermutations(int n, int k)
  {
    int top = factorial(n);
    int bottom = factorial(k);
    return (top/bottom);
  }
  
  public static void main(String[] args)
  {
    int n = Integer.parseInt(args[0]);
    int k = Integer.parseInt(args[1]);
    
    Sample f = new Sample();
    int res;
    if(n > k)
    {
      res = f.numPermutations(n, k);
      System.out.println(res);
    }
    else if(n == k)
    {
      res = f.numPermutations(n, 2);
      System.out.println(res);
    }
    else
    {
      res = f.numPermutations(10, 2);
      System.out.println(res);
    }
  }
}