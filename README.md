## LittleFuzz

A tiny reflection-based fuzzer written in Java, perfect for unit-testing. Its purpose is to assign random 
values to member fields using with customizable value generation and field discovery strategies. 

### Requirements (using)

You need to be running at least JDK 17

### Requirements (building)

JDK 17, Maven 3.9.6 or later

### Usage

Assuming you're using Maven, just add this to your pom.xml

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz</artifactId>
      <version>1.0.0</version>
    </dependency>

First you'll have to create an instance of the `de.codesourcery.littlefuzz.core.Fuzzer`:

    Fuzzer fuzzer = new Fuzzer();

Note that this will initialize the fuzzer with an auto-generated 64-bit random seed. There's also a constructor
to create an instance with a specific/fixed random seed, useful if you need reproducible field values.

The fuzzer comes with a few basic rules for JDK built-in data types like long,String,short,etc that can 
be enabled like so:

    // field values will never get assigned the value they already have.
    // Equality comparisons will performed using the 
    fuzzer.setupDefaultRules(true); 

You can register custom fuzzing rules (`de.codesourcery.littlefuzz.core.Fuzzer.IFuzzingRule`) based on a field's 
declaring class and name or based on the field's type using the `addFieldRule()` , `setFieldRule()`, 
`addTypeRule()` and `setTypeRule()` methods.

The difference between the `addXXX()` and `setXXX()` rules is that the `addXXX()` methods will fail when trying to 
to register a rule more than once for any given type/field while the `setXXX()` methods will just overwrite any
rule that may have been been already assigned.

        fuzzer.addFieldRule( SomeClass.class, "b", (context, setter) -> {} );
        // a rule that just unconditionally increments the field's value by one
        fuzzer.addTypeRule( (context,setter) -> setter.set( (int) context.getFieldValue() + 1), Integer.TYPE);

        // a rule that uses the fuzzer's rand
        fuzzer.addTypeRule( (context,setter) -> setter.set( (int) context.getFieldValue() + 1), Integer.TYPE);


To decide how to randomize a field, the fuzzer uses the following algorithm:

1. Check if a fuzzing rule with the field's name and declaring class exists. If it does, use that rule.
2. Check if there's a fuzzing rule matching the field's type. If it does, use that rule. 
3. Throw a `RuntimeException` complaining that no rule for a field could be found.

 