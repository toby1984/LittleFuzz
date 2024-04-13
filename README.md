## LittleFuzz

A tiny reflection-based fuzzer written in Java, perfect for unit-testing. Its purpose is to assign random 
values to member fields using customizable value generation and field discovery strategies. 

### Requirements (using)

You need to be running at least JDK 17

### Requirements (building)

JDK 17, Maven 3.9.6 or later

To publish to Maven Central, use `mvn -Prelease release:prepare release:perform`.

### Usage

Assuming you're using Maven, just add this to your pom.xml

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz-core</artifactId>
      <version>1.0.0</version>
    </dependency>

First you'll have to create an instance of the `de.codesourcery.littlefuzz.core.Fuzzer`:

    Fuzzer fuzzer = new Fuzzer();

You can register fuzzing rules (`de.codesourcery.littlefuzz.core.IFuzzingRule`) based on a field's 
declaring class and name or based on the field's type using the `addFieldRule()` , `setFieldRule()`, 
`addTypeRule()` and `setTypeRule()` methods.

By default, all non-static member fields of a class (except any `this$<number>` references to enclosing classes)
will be fuzzed. You can customize this behaviour by using the `setFieldResolver(IFieldResolver)` method.

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

You can configure a custom algorithm using the `setRuleResolver(IRuleResolver)` method.

# Extras

Additionally, there's the littlefuzz-extra module that comes with 

- a wrapper for `IFieldValueGenerator` instances that makes sure the generated value is never the current field value
- A class that provides some helper methods for generating random field values based on `java.util.RandomGenerator`.

To use it, just add this to your pom.xml

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz-extra</artifactId>
      <version>1.0.0</version>
    </dependency>
 